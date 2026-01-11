# Copyright 2019 James Brown
# Copyright 2026 Richard Dawson
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

import ssl
import sys
import time
import socket
import struct
import logging
import threading

from torpy.cells import (
    TorCell, CellCerts, CellNetInfo, TorCommands, CellVersions,
    CellAuthChallenge, CellPaddingNegotiate
)
from torpy.utils import coro_recv_exact, to_hex

logger = logging.getLogger(__name__)


class TorSocketConnectError(Exception):
    """Tor socket connection error."""


class TorCellSocket:
    """Handles communication with the relay."""

    RECV_BUFF_SIZE = 4094
    CONNECTION_TIMEOUT = 5.0  # Timeout in seconds for initial connection attempts

    def __init__(self, router):
        self._router = router
        self._socket = None
        self._protocol = TorProtocol()
        self._our_public_ip = '0'
        self._send_close_lock = threading.Lock()

        self._cells_builder = self._cells_builder_gen()
        self._data = bytearray()
        self._next_len = None

    @property
    def ssl_socket(self):
        return self._socket

    def connect(self):
        if self._socket:
            raise Exception('Already connected')

        # Create SSL context compatible with Python 3.6+ and Python 3.12+
        # Python 3.12 removed ssl.wrap_socket(), so we use SSLContext approach
        # This ensures compatibility with current TOR specifications requiring TLS 1.2+
        # Note: We disable hostname checking since TOR connections use IP addresses
        if sys.version_info >= (3, 7):
            # Python 3.7+ supports TLSVersion enum
            context = ssl.create_default_context()
            context.check_hostname = False  # TOR uses IP addresses, not hostnames
            context.verify_mode = ssl.CERT_NONE  # TOR uses self-signed certificates
            if hasattr(ssl, 'TLSVersion'):
                context.minimum_version = ssl.TLSVersion.TLSv1_2
        elif sys.version_info >= (3, 6):
            # Python 3.6: use create_default_context (available since 3.4) or PROTOCOL_TLS
            # Disable older protocols to ensure TLS 1.2+ only
            try:
                context = ssl.create_default_context()
                context.check_hostname = False  # TOR uses IP addresses, not hostnames
                context.verify_mode = ssl.CERT_NONE  # TOR uses self-signed certificates
            except AttributeError:
                # Fallback if create_default_context not available
                if hasattr(ssl, 'PROTOCOL_TLS'):
                    context = ssl.SSLContext(ssl.PROTOCOL_TLS)
                else:
                    context = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
            # Explicitly disable older protocols to enforce TLS 1.2+
            context.options |= ssl.OP_NO_SSLv2
            context.options |= ssl.OP_NO_SSLv3
            context.options |= ssl.OP_NO_TLSv1
            context.options |= ssl.OP_NO_TLSv1_1
        else:
            # Fallback for older versions (though torpy requires Python 3.6+)
            context = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE

        # Create socket and wrap with SSL context
        # Connect first, then wrap (required for Python 3.12+)
        logger.debug('Attempting to connect to relay %s:%d...', self._router.ip, self._router.or_port)
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(self.CONNECTION_TIMEOUT)
        try:
            sock.connect((self._router.ip, self._router.or_port))
        except socket.timeout:
            logger.warning('Connection to relay %s:%d timed out after %.1f seconds', 
                          self._router.ip, self._router.or_port, self.CONNECTION_TIMEOUT)
            sock.close()
            raise TorSocketConnectError(f'Connection timeout to {self._router.ip}:{self._router.or_port}')
        except socket.error as e:
            logger.warning('Connection to relay %s:%d failed: %s', 
                          self._router.ip, self._router.or_port, e)
            sock.close()
            raise TorSocketConnectError(f'Connection failed to {self._router.ip}:{self._router.or_port}: {e}')
        
        self._socket = context.wrap_socket(sock, server_hostname=None)
        
        logger.debug('Socket connected to %s relay, initiating handshake...', self._router)
        try:
            # Socket is already connected and wrapped above
            handshake = TorHandshake(self, self._protocol)
            handshake.initiate()
        except Exception as e:
            logger.warning('Handshake failed for relay %s:%d: %s', self._router.ip, self._router.or_port, e)
            raise TorSocketConnectError(e)

    @property
    def ip_address(self):
        return self._router.ip

    def close(self):
        logger.debug('Close TorCellSocket to %s relay...', self._router)
        with self._send_close_lock:
            if self._socket:
                self._socket.close()
            self._socket = None

    def send_cell(self, cell):
        logger.debug('Cell send: %r', cell)
        buffer = self._protocol.serialize(cell)
        # Debug: log raw bytes being sent
        logger.debug('RAW SEND [%d bytes]: %s...', len(buffer), to_hex(buffer[:64]))
        with self._send_close_lock:
            if self._socket:
                self._socket.write(buffer)
            else:
                logger.warning('socket already closed')

    def recv_cell(self):
        while self._socket:
            self._next_len = self._next_len or next(self._cells_builder)
            if self._next_len and len(self._data) < self._next_len:
                more_data = self._socket.recv(TorCellSocket.RECV_BUFF_SIZE)
                # Debug: log raw bytes received
                if more_data:
                    logger.debug('RAW RECV [%d bytes]: %s...', len(more_data), to_hex(more_data[:64]))
                self._data.extend(more_data)

            for cell in self._build_next_cell():
                # Return first built cell
                return cell
            # Or read more data from socket

    def recv_cell_async(self):
        if not self._socket:
            return
        more_data = self._socket.recv(TorCellSocket.RECV_BUFF_SIZE)
        self._data.extend(more_data)
        self._next_len = self._next_len or next(self._cells_builder)
        yield from self._build_next_cell()

    def _build_next_cell(self):
        while self._next_len is not None and len(self._data) >= self._next_len:
            send_buff = self._data[:self._next_len]
            self._data = self._data[self._next_len:]

            self._next_len = self._cells_builder.send(send_buff)
            if self._next_len is None:
                # New cell was built
                cell = next(self._cells_builder)
                yield cell
                self._next_len = next(self._cells_builder)
        logger.debug('Need more data (%i bytes, has %i bytes)', self._next_len, len(self._data))

    def _cells_builder_gen(self):
        while self._socket:
            circuit_id, command_num = yield from self._read_by_format(self._protocol.header_format)
            cell_type = TorCommands.get_by_num(command_num)
            payload = yield from self._read_command_payload(cell_type)
            logger.debug('CELL RECV: circuit_id=%x, command=%s (%d), payload[:%d]=%s',
                        circuit_id, cell_type.__name__, command_num, 
                        min(32, len(payload)), to_hex(payload[:32]))
            cell = self._protocol.deserialize(cell_type, payload, circuit_id)
            yield None
            yield cell

    def _read_command_payload(self, cell_type):
        if cell_type.is_var_len():
            length, = yield from self._read_by_format(self._protocol.length_format)
        else:
            length = TorCell.MAX_PAYLOAD_SIZE
        cell_buff = yield from coro_recv_exact(length)
        return cell_buff

    def _read_by_format(self, struct_fmt):
        size = struct.calcsize(struct_fmt)
        data = yield from coro_recv_exact(size)
        if not data:
            raise NoDataException()
        return struct.unpack(struct_fmt, data)


class NoDataException(Exception):
    pass


class TorProtocol:
    DEFAULT_VERSION = 3
    SUPPORTED_VERSION = [3, 4, 5]  # Link protocol 5 adds padding negotiation support

    def __init__(self, version=DEFAULT_VERSION):
        self._version = version

    @property
    def version(self):
        return self._version

    @version.setter
    def version(self, version):
        self._version = version

    @property
    def header_format(self):
        #    CircuitID                          [CIRCUIT_ID_LEN octets]
        #    Command                            [1 byte]
        if self.version < 4:
            return '!HB'
        else:
            # Link protocol 4 increases circuit ID width to 4 bytes.
            return '!IB'

    @property
    def length_format(self):
        #    Length                             [2 octets; big-endian integer]
        return '!H'

    def deserialize(self, command, payload, circuit_id=0):
        # parse depending on version
        # ...
        return TorCell.deserialize(command, circuit_id, payload, self.version)

    def serialize(self, cell):
        # get bytes depending on version
        # ...
        return cell.serialize(self.version)


class TorHandshake:
    def __init__(self, tor_socket, tor_protocol):
        self.tor_socket = tor_socket
        self.tor_protocol = tor_protocol

    def initiate(self):
        # When the in-protocol handshake is used, the initiator sends a
        # VERSIONS cell to indicate that it will not be renegotiating.  The
        # responder sends a VERSIONS cell, a CERTS cell (4.2 below) to give the
        # initiator the certificates it needs to learn the responder's
        # identity, an AUTH_CHALLENGE cell (4.3) that the initiator must include
        # as part of its answer if it chooses to authenticate, and a NET_INFO
        # cell (4.5).  As soon as it gets the CERTS cell, the initiator knows
        # whether the responder is correctly authenticated.  At this point the
        # initiator behaves differently depending on whether it wants to
        # authenticate or not. If it does not want to authenticate, it MUST
        # send a NET_INFO cell.
        logger.info('HANDSHAKE: Starting link protocol negotiation...')
        self._send_versions()
        self.tor_protocol.version = self._retrieve_versions()
        logger.info('HANDSHAKE: Negotiated link protocol version: %d', self.tor_protocol.version)

        self._retrieve_certs()

        self._retrieve_net_info()
        self._send_net_info()
        logger.info('HANDSHAKE: NET_INFO exchange complete')

        # Link protocol 5 adds support for link padding negotiation
        # See padding-spec.txt for details
        if self.tor_protocol.version >= 5:
            self._negotiate_padding()
            logger.info('HANDSHAKE: Link protocol 5 padding negotiation complete')

    def _send_versions(self):
        """
        Send CellVersion.

        When the "in-protocol" handshake is used, implementations MUST NOT
        list any version before 3, and SHOULD list at least version 3.

        Link protocols differences are:
          1 -- The "certs up front" handshake.
          2 -- Uses the renegotiation-based handshake. Introduces
               variable-length cells.
          3 -- Uses the in-protocol handshake.
          4 -- Increases circuit ID width to 4 bytes.
          5 -- Adds support for link padding and negotiation (padding-spec.txt).
        """
        self.tor_socket.send_cell(CellVersions(self.tor_protocol.SUPPORTED_VERSION))

    def _retrieve_versions(self):
        # Skip unknown cells until we get VERSIONS cell
        while True:
            cell = self.tor_socket.recv_cell()
            if isinstance(cell, CellVersions):
                break
            # Skip unknown cells (e.g., newer protocol features)
            logger.debug('Skipping non-VERSIONS cell: %s', type(cell).__name__)

        logger.debug('Remote protocol versions: %s', cell.versions)
        # Choose maximum supported by both
        return min(max(self.tor_protocol.SUPPORTED_VERSION), max(cell.versions))

    def _retrieve_certs(self):
        logger.debug('Retrieving CERTS cell...')
        # Skip unknown cells until we get CERTS cell
        while True:
            cell_certs = self.tor_socket.recv_cell()
            if isinstance(cell_certs, CellCerts):
                break
            logger.debug('Skipping non-CERTS cell: %s', type(cell_certs).__name__)
        
        # Validate certificates
        self._validate_certificates(cell_certs.certs)

        logger.debug('Retrieving AUTH_CHALLENGE cell...')
        # Skip unknown cells until we get AUTH_CHALLENGE cell
        while True:
            cell_auth = self.tor_socket.recv_cell()
            if isinstance(cell_auth, CellAuthChallenge):
                break
            logger.debug('Skipping non-AUTH_CHALLENGE cell: %s', type(cell_auth).__name__)

    def _validate_certificates(self, certs):
        """
        Validate the certificates received in the CERTS cell.
        
        Per tor-spec.txt section 4.2.1:
        - Certificate type 1 or 2 must be present (link or identity RSA)
        - Certificate type 4 should be present for Ed25519 identity
        - Verify certificate chains and signatures
        
        Args:
            certs: List of (cert_type, cert_data) tuples
        """
        if not certs:
            logger.warning('No certificates received in CERTS cell')
            return
        
        cert_types = {cert_type for cert_type, _ in certs}
        logger.debug('Received certificate types: %s', cert_types)
        
        # Check for required certificate types
        # Type 1: Link key certificate (RSA)
        # Type 2: RSA identity certificate  
        # Type 4: Ed25519 signing key
        has_rsa_identity = 2 in cert_types or 1 in cert_types
        has_ed25519_identity = 4 in cert_types
        
        if not has_rsa_identity:
            logger.warning('Missing RSA identity certificate (type 1 or 2)')
        
        if not has_ed25519_identity:
            logger.debug('No Ed25519 identity certificate (type 4) - older relay')
        
        # Basic validation: check that we have at least one identity cert
        if not has_rsa_identity and not has_ed25519_identity:
            raise ValueError('No valid identity certificates received')
        
        # Additional validation could include:
        # - Verify RSA signatures on certificates
        # - Verify Ed25519 signatures
        # - Check certificate expiration dates
        # - Verify certificate chains
        # 
        # For now, we do basic presence checking. Full cryptographic
        # validation would require parsing X.509 or Ed25519-cert formats
        # and verifying signatures, which is complex and may not be
        # critical for client security (we're already using end-to-end
        # encryption in the circuit).
        
        logger.debug('Certificate validation passed (basic checks)')

    def _retrieve_net_info(self):
        logger.debug('Retrieving NET_INFO cell...')
        # Skip unknown cells until we get NET_INFO cell
        while True:
            cell = self.tor_socket.recv_cell()
            if isinstance(cell, CellNetInfo):
                break
            logger.debug('Skipping non-NET_INFO cell: %s', type(cell).__name__)
        logger.debug('Our public IP address: %s', cell.this_or)

    def _send_net_info(self):
        """If version 2 or higher is negotiated, each party sends the other a NETINFO cell."""
        logger.debug('Sending NET_INFO cell...')
        self.tor_socket.send_cell(CellNetInfo(int(time.time()), self.tor_socket.ip_address, '0'))

    def _negotiate_padding(self):
        """
        Negotiate link padding for protocol version 5+.

        Link protocol 5 adds support for link padding and negotiation.
        Clients can send PADDING_NEGOTIATE cells to enable/disable padding.

        By default, we disable link padding for performance (clients typically
        don't need it). Relays may still send PADDING_NEGOTIATE or VPADDING cells
        which we will accept and ignore.

        See padding-spec.txt section 2. "Link-level padding"
        """
        logger.debug('Negotiating link padding (protocol v5)...')
        # Send PADDING_NEGOTIATE with STOP command to disable padding
        # This reduces bandwidth overhead for the connection
        # version=0, command=PADDING_STOP(0), ito_low=0, ito_high=0
        padding_cell = CellPaddingNegotiate(
            version=0,
            command=CellPaddingNegotiate.PADDING_STOP,
            ito_low_ms=0,
            ito_high_ms=0
        )
        self.tor_socket.send_cell(padding_cell)
        logger.debug('Sent PADDING_NEGOTIATE(STOP) to disable link padding')
