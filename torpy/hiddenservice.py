# Copyright 2019 James Brown
# Copyright 2025 Richard Dawson
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

import math
import time
import struct
import logging
from base64 import b32decode, b32encode
from typing import TYPE_CHECKING, Optional

from torpy.cells import CellRelayRendezvous2
from torpy.utils import AuthType
from torpy.parsers import IntroPointParser, HSDescriptorParser
from torpy.crypto_common import sha1, aes_update, aes_ctr_decryptor, b64decode, curve25519_public_from_bytes

# V3 hidden service support
from torpy.hs_ntor import (
    get_time_period_num,
    derive_blinded_pubkey,
    build_subcredential,
    verify_hs_address,
    HSNtorHandshake,
)
from torpy.hs_descriptor import (
    decrypt_v3_descriptor,
    parse_link_specifiers,
    V3HSDescriptor,
)

if TYPE_CHECKING:
    from torpy.circuit import TorCircuit

logger = logging.getLogger(__name__)


# tor ref: handle_control_hsfetch
# tor ref: connection_ap_handle_onion
class HiddenService:
    # Length of 'y' portion of 'y.onion' URL.
    REND_SERVICE_ID_LEN_BASE32 = 16
    # Length of a binary-encoded rendezvous service ID.
    REND_SERVICE_ID_LEN = 10

    # ...
    ED25519_PUBKEY_LEN = 32

    # The amount of bytes we use from the address checksum.
    HS_SERVICE_ADDR_CHECKSUM_LEN_USED = 2

    # Length of the binary encoded service address which is of course before the
    # base32 encoding. Construction is:
    #    PUBKEY || CHECKSUM || VERSION
    # with 1 byte VERSION and 2 bytes CHECKSUM. The following is 35 bytes.
    HS_SERVICE_ADDR_LEN = (ED25519_PUBKEY_LEN + HS_SERVICE_ADDR_CHECKSUM_LEN_USED + 1)

    # Length of 'y' portion of 'y.onion' URL. This is base32 encoded and the
    # length ends up to 56 bytes (not counting the terminated NUL byte.)
    HS_SERVICE_ADDR_LEN_BASE32 = math.ceil(HS_SERVICE_ADDR_LEN * 8 / 5)

    HS_NO_AUTH = (None, AuthType.No)

    def __init__(self, onion_address, descriptor_cookie=None, auth_type=AuthType.No,
                 client_auth_key: Optional[bytes] = None):
        """
        Initialize a hidden service connection.
        
        Args:
            onion_address: The .onion address (v2 or v3)
            descriptor_cookie: V2 descriptor cookie for authorization
            auth_type: V2 authorization type (Basic or Stealth)
            client_auth_key: V3 client authorization key (x25519 private key)
        """
        self._onion_address, self._permanent_id, onion_identity_pk = self.parse_onion(onion_address)
        
        # Detect v2 vs v3
        if onion_identity_pk is not None:
            # V3 hidden service (56-character address)
            self._version = 3
            self._identity_pubkey = onion_identity_pk  # Ed25519 public key
            self._onion_identity_pk = None  # Not used for v3
            self._client_auth_key = client_auth_key
            
            # Verify the address checksum
            is_valid, _ = verify_hs_address(self._onion_address)
            if not is_valid:
                raise ValueError(f'Invalid v3 onion address checksum: {onion_address}')
            
            logger.info('Initialized v3 hidden service: %s', self._onion_address[:16] + '...')
        else:
            # V2 hidden service (16-character address)
            self._version = 2
            self._identity_pubkey = None
            self._onion_identity_pk = None
            self._client_auth_key = None
        
        self._descriptor_cookie = b64decode(descriptor_cookie) if descriptor_cookie else None
        self._auth_type = auth_type
        
        # V2-specific auth validation
        if self._version == 2:
            if descriptor_cookie and auth_type == AuthType.No:
                raise RuntimeError('You must specify auth type')
            if not descriptor_cookie and auth_type != AuthType.No:
                raise RuntimeError('You must specify descriptor cookie')

    @staticmethod
    def normalize_onion(onion_address):
        if onion_address.endswith('.onion'):
            onion_address = onion_address[:-6].rsplit('.', 1)[-1]

        if len(onion_address) != HiddenService.REND_SERVICE_ID_LEN_BASE32 and \
           len(onion_address) != HiddenService.HS_SERVICE_ADDR_LEN_BASE32:
            raise Exception(f'Unknown onion address: {onion_address}')

        return onion_address

    @staticmethod
    def parse_onion(onion_address):
        onion_address = HiddenService.normalize_onion(onion_address)

        if len(onion_address) == HiddenService.REND_SERVICE_ID_LEN_BASE32:
            permanent_id = b32decode(onion_address.upper())
            assert len(permanent_id) == HiddenService.REND_SERVICE_ID_LEN, 'You must specify valid V2 onion hostname'
            return onion_address, permanent_id, None
        elif len(onion_address) == HiddenService.HS_SERVICE_ADDR_LEN_BASE32:
            # tor ref: hs_parse_address
            decoded = b32decode(onion_address.upper())
            pubkey = decoded[:HiddenService.ED25519_PUBKEY_LEN]
            # checksum decoded[self.ED25519_PUBKEY_LEN:self.ED25519_PUBKEY_LEN + self.HS_SERVICE_ADDR_CHECKSUM_LEN_USED]
            # version decoded[self.ED25519_PUBKEY_LEN + self.HS_SERVICE_ADDR_CHECKSUM_LEN_USED:]
            return onion_address, None, pubkey
            # fetch_v3_desc
            # pick_hsdir_v3
            # directory_launch_v3_desc_fetch

    @property
    def onion(self):
        return self._onion_address

    @property
    def hostname(self):
        return self._onion_address + '.onion'

    @property
    def permanent_id(self):
        """service-id or permanent-id."""
        return self._permanent_id

    @property
    def descriptor_cookie(self):
        return self._descriptor_cookie

    @property
    def auth_type(self):
        return self._auth_type

    @property
    def version(self):
        """Return the hidden service version (2 or 3)."""
        return self._version

    @property
    def identity_pubkey(self):
        """Return the Ed25519 identity public key (v3 only)."""
        return self._identity_pubkey

    @property
    def is_v3(self):
        """Return True if this is a v3 hidden service."""
        return self._version == 3

    # =========================================================================
    # V3 Hidden Service Methods
    # =========================================================================

    def get_blinded_pubkey(self, time_period_num: Optional[int] = None) -> bytes:
        """
        Get the blinded public key for v3 descriptor lookup.
        
        Args:
            time_period_num: Time period number (defaults to current)
            
        Returns:
            32-byte blinded public key
        """
        if self._version != 3:
            raise RuntimeError('get_blinded_pubkey only available for v3 hidden services')
        
        if time_period_num is None:
            time_period_num = get_time_period_num()
        
        return derive_blinded_pubkey(self._identity_pubkey, time_period_num)

    def get_subcredential(self, time_period_num: Optional[int] = None) -> bytes:
        """
        Get the subcredential for v3 descriptor decryption.
        
        Args:
            time_period_num: Time period number (defaults to current)
            
        Returns:
            32-byte subcredential
        """
        if self._version != 3:
            raise RuntimeError('get_subcredential only available for v3 hidden services')
        
        if time_period_num is None:
            time_period_num = get_time_period_num()
        
        blinded_pubkey = self.get_blinded_pubkey(time_period_num)
        return build_subcredential(self._identity_pubkey, blinded_pubkey)

    def get_descriptor_id_v3(self, replica: int = 0, 
                              time_period_num: Optional[int] = None) -> bytes:
        """
        Get the v3 descriptor ID for HSDir lookup.
        
        Args:
            replica: Replica number (0 or 1)
            time_period_num: Time period number (defaults to current)
            
        Returns:
            32-byte descriptor ID
        """
        if self._version != 3:
            raise RuntimeError('get_descriptor_id_v3 only available for v3 hidden services')
        
        if time_period_num is None:
            time_period_num = get_time_period_num()
        
        blinded_pubkey = self.get_blinded_pubkey(time_period_num)
        
        # Descriptor ID is derived from blinded key
        from torpy.crypto_common import sha3_256
        import struct
        
        TIME_PERIOD_LENGTH = 1440 * 60
        desc_id_input = (
            b"store-at-idx" +
            blinded_pubkey +
            struct.pack(">Q", replica) +
            struct.pack(">Q", TIME_PERIOD_LENGTH) +
            struct.pack(">Q", time_period_num)
        )
        
        return sha3_256(desc_id_input)

    # =========================================================================
    # V2 Hidden Service Methods
    # =========================================================================

    def _get_secret_id(self, replica):
        """
        Get secret_id by replica number.

        rend-spec.txt
        1.3.

        "time-period" changes periodically as a function of time and
        "permanent-id". The current value for "time-period" can be calculated
        using the following formula:

          time-period = (current-time + permanent-id-byte * 86400 / 256)
                          / 86400
        """
        # tor ref: get_secret_id_part_bytes
        permanent_byte = self._permanent_id[0]
        time_period = int((int(time.time()) + (permanent_byte * 86400 / 256)) / 86400)
        if self._descriptor_cookie and self._auth_type == AuthType.Stealth:
            buff = struct.pack('!I16sB', time_period, self._descriptor_cookie, replica)
        else:
            buff = struct.pack('!IB', time_period, replica)
        return sha1(buff)

    def get_descriptor_id(self, replica):
        # tor ref: rend_compute_v2_desc_id
        # Calculate descriptor ID: H(permanent-id | secret-id-part)
        buff = self._permanent_id + self._get_secret_id(replica)
        return sha1(buff)


class HiddenServiceConnector:
    def __init__(self, circuit, consensus):
        self._circuit = circuit
        self._consensus = consensus

    def get_responsibles_dir(self, hidden_service):
        """
        Get responsible HSDirs for the hidden service.
        
        Args:
            hidden_service: HiddenService object (v2 or v3)
            
        Yields:
            ResponsibleDir objects
        """
        if hidden_service.is_v3:
            # V3 hidden service - use v3 HSDir selection
            time_period_num = get_time_period_num()
            blinded_pubkey = hidden_service.get_blinded_pubkey(time_period_num)
            
            # Get v3 responsible HSDirs (yields router, replica tuples)
            # The generator handles 2 replicas internally, each with 4 HSDirs
            for responsible_router, replica in self._consensus.get_responsibles_v3(
                blinded_pubkey,
                time_period_num,
                spread=4
            ):
                yield ResponsibleDir(responsible_router, replica, self._circuit, self._consensus)
        else:
            # V2 hidden service - use v2 HSDir selection
            for i, responsible_router in enumerate(self._consensus.get_responsibles(hidden_service)):
                replica = 1 if i >= 3 else 0
                yield ResponsibleDir(responsible_router, replica, self._circuit, self._consensus)


class EncPointsBuffer:
    # /** Length of our symmetric cipher's keys of 128-bit. */
    CIPHER_KEY_LEN = 16
    # /** Length of our symmetric cipher's IV of 128-bit. */
    CIPHER_IV_LEN = 16
    # /** Length of our symmetric cipher's keys of 256-bit. */
    CIPHER256_KEY_LEN = 32
    # /** Length of client identifier in encrypted introduction points for hidden
    #  * service authorization type 'basic'. */
    REND_BASIC_AUTH_CLIENT_ID_LEN = 4
    # /** Multiple of the number of clients to which the real number of clients
    #  * is padded with fake clients for hidden service authorization type
    #  * 'basic'. */
    REND_BASIC_AUTH_CLIENT_MULTIPLE = 16
    # /** Length of client entry consisting of client identifier and encrypted
    #  * session key for hidden service authorization type 'basic'. */
    REND_BASIC_AUTH_CLIENT_ENTRY_LEN = REND_BASIC_AUTH_CLIENT_ID_LEN + CIPHER_KEY_LEN

    def __init__(self, crypted_data):
        self._crypted_data = crypted_data
        assert len(crypted_data) > 2, 'Size of crypted data too small'
        self._auth_type = int(crypted_data[0])
        # fmt: off
        self._auth_to_func = {AuthType.Basic: self._decrypt_basic,
                              AuthType.Stealth: self._decrypt_stealth}
        # fmt: on

    @property
    def auth_type(self):
        return self._auth_type

    def decrypt(self, descriptor_cookie):
        # tor ref: rend_decrypt_introduction_points
        return self._auth_to_func[self._auth_type](descriptor_cookie)

    def _decrypt_basic(self, descriptor_cookie):
        assert self._crypted_data[0] == AuthType.Basic
        block_count = self._crypted_data[1]
        entries_len = block_count * self.REND_BASIC_AUTH_CLIENT_MULTIPLE * self.REND_BASIC_AUTH_CLIENT_ENTRY_LEN
        assert len(self._crypted_data) > 2 + entries_len + self.CIPHER_IV_LEN, 'Size of crypted data too small'
        iv = self._crypted_data[2 + entries_len:2 + entries_len + self.CIPHER_IV_LEN]
        client_id = sha1(descriptor_cookie + iv)[:4]
        session_key = self._get_session_key(self._crypted_data[2:2 + entries_len], descriptor_cookie, client_id)
        d = aes_ctr_decryptor(session_key, iv)
        data = self._crypted_data[2 + entries_len + self.CIPHER_IV_LEN:]
        return d.update(data)

    def _get_session_key(self, data, descriptor_cookie, client_id):
        pos = 0
        d = aes_ctr_decryptor(descriptor_cookie)
        while pos < len(data):
            if data[pos:pos + self.REND_BASIC_AUTH_CLIENT_ID_LEN] == client_id:
                start_key_pos = pos + self.REND_BASIC_AUTH_CLIENT_ID_LEN
                end_key_pos = start_key_pos + self.CIPHER_KEY_LEN
                enc_session_key = data[start_key_pos:end_key_pos]
                return aes_update(d, enc_session_key)
            pos += self.REND_BASIC_AUTH_CLIENT_ENTRY_LEN
        raise Exception('Session key for client {!r} not found'.format(client_id))

    def _decrypt_stealth(self, descriptor_cookie):
        assert len(self._crypted_data) > 2 + self.CIPHER_IV_LEN, 'Size of encrypted data is too small'
        assert self._crypted_data[0] == AuthType.Stealth
        iv = self._crypted_data[1:1 + self.CIPHER_IV_LEN]
        d = aes_ctr_decryptor(descriptor_cookie, iv)
        data = self._crypted_data[1 + self.CIPHER_IV_LEN:]
        return d.update(data)


class DescriptorNotAvailable(Exception):
    """Descriptor not found."""


class ResponsibleDir:
    def __init__(self, router, replica, circuit, consensus):
        self._router = router
        self._replica = replica
        self._circuit = circuit
        self._consensus = consensus

    @property
    def replica(self):
        return self._replica

    def get_introductions(self, hidden_service):
        if hidden_service.is_v3:
            # V3 hidden service
            time_period_num = get_time_period_num()
            blinded_pubkey = hidden_service.get_blinded_pubkey(time_period_num)
            response = self._fetch_descriptor(None, is_v3=True, blinded_pubkey=blinded_pubkey)
            for intro_point in self._get_intro_points_v3(response, hidden_service):
                yield intro_point
        else:
            # V2 hidden service
            descriptor_id = hidden_service.get_descriptor_id(self.replica)
            response = self._fetch_descriptor(descriptor_id, is_v3=False)
            for intro_point in self._get_intro_points(response, hidden_service.descriptor_cookie):
                yield intro_point

    def _fetch_descriptor(self, descriptor_id, is_v3=False, blinded_pubkey=None):
        # tor ref: rend_client_fetch_v2_desc
        # tor ref: fetch_v3_desc

        logger.info('Create circuit for hsdir')
        with self._circuit.create_new_circuit(extend_routers=[self._router]) as directory_circuit:
            assert directory_circuit.nodes_count == 2

            with directory_circuit.create_dir_client() as dir_client:
                if is_v3:
                    # V3 descriptor fetch
                    # Path format: /tor/hs/3/<hsdir_index>
                    if blinded_pubkey is None:
                        raise ValueError('V3 descriptor fetch requires blinded_pubkey')
                    
                    # The hsdir_index is the first 8 bytes of blinded_pubkey in base64
                    from base64 import b64encode
                    hsdir_index = b64encode(blinded_pubkey).decode().replace('=', '').replace('+', '-').replace('/', '_')
                    descriptor_path = f'/tor/hs/3/{hsdir_index}'
                    logger.debug('Fetching v3 descriptor: %s', descriptor_path)
                else:
                    # V2 descriptor fetch
                    # tor ref: directory_send_command (DIR_PURPOSE_FETCH_RENDDESC_V2)
                    descriptor_id_str = b32encode(descriptor_id).decode().lower()
                    descriptor_path = f'/tor/rendezvous2/{descriptor_id_str}'
                    logger.debug('Fetching v2 descriptor: %s', descriptor_path)

                status, response = dir_client.get(descriptor_path)
                response = response.decode()
                if status != 200:
                    logger.error('No valid response from hsdir. Status = %r. Body: %r', status, response)
                    raise DescriptorNotAvailable("Couldn't fetch descriptor")

                return response

    def _info_to_router(self, intro_point_info):
        onion_router = self._consensus.get_router(intro_point_info['introduction_point'])
        onion_router.service_key = intro_point_info['service_key']
        onion_router.onion_key = intro_point_info['onion_key']
        return onion_router

    def _get_intro_points_v3(self, response, hidden_service):
        """
        Parse v3 hidden service descriptor and extract introduction points.
        
        Args:
            response: Raw descriptor text
            hidden_service: HiddenService object with v3 details
            
        Yields:
            IntroductionPointV3 objects
        """
        # Parse and decrypt v3 descriptor
        time_period_num = get_time_period_num()
        subcredential = hidden_service.get_subcredential(time_period_num)
        
        try:
            v3_descriptor = V3HSDescriptor(response)
            decrypted = decrypt_v3_descriptor(
                v3_descriptor,
                subcredential,
                x25519_client_key=hidden_service._client_auth_key
            )
            
            # Parse introduction points from decrypted descriptor
            intro_points_data = decrypted.get('introduction-point', [])
            if not intro_points_data:
                logger.warning('No introduction points found in v3 descriptor')
                return
            
            for intro_point_raw in intro_points_data:
                # Parse link specifiers to find router
                link_specifiers = parse_link_specifiers(intro_point_raw.get('link-specifiers', b''))
                
                # Try to find router by fingerprint or ed25519 id
                router = None
                for link_spec in link_specifiers:
                    if link_spec['type'] == 0:  # TLS-over-TCP, IPv4
                        # We have IP and port, try to find in consensus
                        continue
                    elif link_spec['type'] == 2:  # Legacy identity (RSA)
                        fingerprint = link_spec['data'].hex().upper()
                        router = self._consensus.get_router(fingerprint)
                        if router:
                            break
                    elif link_spec['type'] == 3:  # Ed25519 identity
                        # Try to find by ed25519 id in consensus
                        # For now, skip as consensus lookup by ed25519 not implemented
                        continue
                
                if not router:
                    logger.warning('Could not find router in consensus for intro point')
                    continue
                
                # Store v3-specific data on the router
                router.intro_auth_key = intro_point_raw.get('auth-key')
                router.enc_key = intro_point_raw.get('enc-key')
                router.enc_key_cert = intro_point_raw.get('enc-key-cert')
                
                yield IntroductionPointV3(router, self._circuit, intro_point_raw)
                
        except Exception as e:
            logger.error('Failed to parse v3 descriptor: %s', e)
            raise DescriptorNotAvailable(f'Failed to parse v3 descriptor: {e}')

    def _get_intro_points(self, response, descriptor_cookie):
        intro_points_raw_base64 = HSDescriptorParser.parse(response)
        intro_points_raw = b64decode(intro_points_raw_base64)

        # Check whether it's encrypted
        if intro_points_raw[0] == AuthType.Basic or intro_points_raw[0] == AuthType.Stealth:
            if not descriptor_cookie:
                raise Exception('Hidden service needs descriptor_cookie for authorization')
            enc_buff = EncPointsBuffer(intro_points_raw)
            intro_points_raw = enc_buff.decrypt(descriptor_cookie)
        elif descriptor_cookie:
            logger.warning("Descriptor cookie was specified but hidden service hasn't encrypted intro points")

        if not intro_points_raw.startswith(b'introduction-point '):
            raise Exception('Unknown introduction point data received')

        intro_points_raw = intro_points_raw.decode()
        intro_points_info_list = IntroPointParser.parse(intro_points_raw)

        for intro_point_info in intro_points_info_list:
            router = self._info_to_router(intro_point_info)
            yield IntroductionPoint(router, self._circuit)

    def __str__(self):
        """Format ResponsibleDir string representation."""
        return 'ResponsibleDir {}'.format(self._router)


class IntroductionPoint:
    def __init__(self, router, circuit: 'TorCircuit'):
        self._introduction_router = router
        self._circuit = circuit

    def connect(self, hidden_service, rendezvous_cookie):
        # Waiting for CellRelayRendezvous2 in our main circuit
        with self._circuit.create_waiter(CellRelayRendezvous2) as w:
            # Create introduction point circuit
            with self._circuit.create_new_circuit(extend_routers=[self._introduction_router]) as intro_circuit:
                assert intro_circuit.nodes_count == 2

                # V2 uses TAP handshake for introduction
                # Send Introduce1
                extend_node = intro_circuit.rendezvous_introduce(
                    self._circuit,
                    rendezvous_cookie,
                    hidden_service.auth_type,
                    hidden_service.descriptor_cookie,
                )

                rendezvous2_cell = w.get(timeout=10)
                extend_node.complete_handshake(rendezvous2_cell.handshake_data)
                return extend_node


class IntroductionPointV3:
    """V3 hidden service introduction point."""
    
    def __init__(self, router, circuit: 'TorCircuit', intro_data: dict):
        self._introduction_router = router
        self._circuit = circuit
        self._intro_data = intro_data

    def connect(self, hidden_service, rendezvous_cookie):
        """
        Connect to v3 hidden service through this introduction point.
        
        Args:
            hidden_service: HiddenService object
            rendezvous_cookie: Random 20-byte rendezvous cookie
            
        Returns:
            CircuitNode with completed HS-ntor handshake
        """
        # Waiting for CellRelayRendezvous2 in our main circuit
        with self._circuit.create_waiter(CellRelayRendezvous2) as w:
            # Create introduction point circuit
            with self._circuit.create_new_circuit(extend_routers=[self._introduction_router]) as intro_circuit:
                assert intro_circuit.nodes_count == 2

                # V3 uses HS-ntor handshake for introduction
                logger.info('Sending v3 Introduce1 cell...')
                extend_node = intro_circuit.rendezvous_introduce_v3(
                    self._circuit,
                    rendezvous_cookie,
                    hidden_service,
                    self._intro_data,
                )

                rendezvous2_cell = w.get(timeout=10)
                extend_node.complete_handshake(rendezvous2_cell.handshake_data)
                logger.info('V3 rendezvous completed')
                return extend_node
