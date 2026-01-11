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

"""
Hidden Service ntor handshake and blinded key derivation for v3 onion services.

Implements the cryptographic operations defined in rend-spec-v3:
https://gitlab.torproject.org/tpo/core/torspec/-/blob/main/spec/rend-spec-v3.md

Key operations:
- Blinded key derivation (section 2.2)
- HS-ntor handshake (section 3.3)
- Time period calculations (section 2.2.1)
"""

import time
import struct
import hashlib
import logging
from typing import Tuple, Optional

from torpy.crypto_common import (
    sha3_256,
    hkdf_sha256,
    curve25519_private,
    curve25519_get_shared,
    curve25519_public_from_private,
    curve25519_public_from_bytes,
    curve25519_to_bytes,
    ed25519_public_from_bytes,
    ed25519_to_bytes,
)

logger = logging.getLogger(__name__)

# =============================================================================
# Constants from rend-spec-v3
# =============================================================================

# Time period length in seconds (default: 1440 minutes = 24 hours)
TIME_PERIOD_LENGTH = 1440 * 60

# Number of seconds from Unix epoch to the start of time periods
# This is the SRV voting interval start (midnight UTC on the day of first commit)
TIME_PERIOD_ROTATION_OFFSET = 12 * 60 * 60  # 12 hours

# Protocol identifier for hs-ntor
HS_NTOR_PROTOID = b"tor-hs-ntor-curve25519-sha3-256-1"

# Key expansion info strings
HS_NTOR_KEY_EXPAND = HS_NTOR_PROTOID + b":hs_key_expand"
HS_NTOR_MAC = HS_NTOR_PROTOID + b":hs_mac"
HS_NTOR_VERIFY = HS_NTOR_PROTOID + b":hs_verify"

# Credential derivation
CREDENTIAL_BYPASS_STR = b"credential"
SUBCREDENTIAL_STR = b"subcredential"

# Blinded key derivation
BLIND_STRING = b"Derive temporary signing key"
BLIND_PARAM_STR = b"key-blind"

# Ed25519 base point order (for blinding calculations)
ED25519_BASEPOINT_ORDER = (
    2**252 + 27742317777372353535851937790883648493
)


# =============================================================================
# Time Period Functions
# =============================================================================

def get_time_period_num(timestamp: Optional[int] = None) -> int:
    """
    Calculate the time period number for a given timestamp.
    
    Per rend-spec-v3 section 2.2.1:
    time_period_num = (current_time - TIME_PERIOD_ROTATION_OFFSET) / TIME_PERIOD_LENGTH
    
    Args:
        timestamp: Unix timestamp (defaults to current time)
        
    Returns:
        int: Time period number
    """
    if timestamp is None:
        timestamp = int(time.time())
    return (timestamp - TIME_PERIOD_ROTATION_OFFSET) // TIME_PERIOD_LENGTH


def get_time_period_length() -> int:
    """Get the time period length in seconds."""
    return TIME_PERIOD_LENGTH


def get_srv_start_time(time_period_num: int) -> int:
    """
    Get the start time of a given time period.
    
    Args:
        time_period_num: The time period number
        
    Returns:
        int: Unix timestamp of period start
    """
    return time_period_num * TIME_PERIOD_LENGTH + TIME_PERIOD_ROTATION_OFFSET


def get_next_time_period_num(timestamp: Optional[int] = None) -> int:
    """Get the next time period number."""
    return get_time_period_num(timestamp) + 1


# =============================================================================
# Credential and Subcredential Derivation
# =============================================================================

def build_credential(identity_pubkey: bytes) -> bytes:
    """
    Build the credential from the service's identity public key.
    
    Per rend-spec-v3:
    credential = H("credential" | public-identity-key)
    
    Args:
        identity_pubkey: 32-byte Ed25519 public key
        
    Returns:
        bytes: 32-byte credential
    """
    return sha3_256(CREDENTIAL_BYPASS_STR + identity_pubkey)


def build_subcredential(identity_pubkey: bytes, blinded_pubkey: bytes) -> bytes:
    """
    Build the subcredential for a given time period.
    
    Per rend-spec-v3:
    subcredential = H("subcredential" | credential | blinded-public-key)
    
    Args:
        identity_pubkey: 32-byte Ed25519 identity public key
        blinded_pubkey: 32-byte blinded public key for current time period
        
    Returns:
        bytes: 32-byte subcredential
    """
    credential = build_credential(identity_pubkey)
    return sha3_256(SUBCREDENTIAL_STR + credential + blinded_pubkey)


# =============================================================================
# Blinded Key Derivation
# =============================================================================

def _clamp_ed25519_scalar(s: bytes) -> bytes:
    """
    Clamp an Ed25519 scalar per RFC 8032.
    
    This ensures the scalar is in the correct form for Ed25519 operations.
    """
    s_list = list(s)
    s_list[0] &= 248
    s_list[31] &= 127
    s_list[31] |= 64
    return bytes(s_list)


def _derive_blind_factor(identity_pubkey: bytes, time_period_num: int, 
                          nonce: bytes = b"") -> bytes:
    """
    Derive the blinding factor for a given time period.
    
    Per rend-spec-v3 section 2.2:
    h = H(BLIND_STRING | A | s | B | N)
    
    Where:
    - A is the Ed25519 identity public key
    - s is a secret (empty for public derivation)
    - B is the Ed25519 basepoint (encoded, but we include period info)
    - N is the nonce (usually includes time period)
    
    Args:
        identity_pubkey: 32-byte Ed25519 public key
        time_period_num: Current time period number
        nonce: Optional additional nonce data
        
    Returns:
        bytes: 32-byte blinding factor
    """
    # Build the param string: N = int64(period_num) || int64(period_length) || nonce
    period_info = struct.pack(">QQ", time_period_num, TIME_PERIOD_LENGTH) + nonce
    
    # H(BLIND_STRING | A | s | B | N)
    # For public derivation, s is empty
    # B is represented implicitly through the protocol
    blind_input = BLIND_STRING + identity_pubkey + period_info
    
    h = sha3_256(blind_input)
    
    # Reduce modulo the Ed25519 base point order
    # and clamp to ensure valid scalar
    h_int = int.from_bytes(h, 'little') % ED25519_BASEPOINT_ORDER
    blind_factor = h_int.to_bytes(32, 'little')
    
    return blind_factor


def derive_blinded_pubkey(identity_pubkey: bytes, time_period_num: int,
                          nonce: bytes = b"") -> bytes:
    """
    Derive the blinded public key for a v3 hidden service.
    
    Per rend-spec-v3 section 2.2:
    A' = h * A  (Ed25519 scalar point multiplication)
    
    Uses PyNaCl's crypto_scalarmult_ed25519_noclamp for proper Ed25519
    point multiplication.
    
    Args:
        identity_pubkey: 32-byte Ed25519 identity public key
        time_period_num: Time period number
        nonce: Optional nonce for key derivation
        
    Returns:
        bytes: 32-byte blinded public key
    """
    try:
        from nacl.bindings import crypto_scalarmult_ed25519_noclamp
    except ImportError:
        raise ImportError("PyNaCl is required for v3 hidden service blinded key derivation. "
                          "Install it with: pip install pynacl")
    
    # Derive the blinding factor
    blind_factor = _derive_blind_factor(identity_pubkey, time_period_num, nonce)
    
    # Perform Ed25519 scalar-point multiplication: A' = h * A
    # This is the proper cryptographic operation per rend-spec-v3
    try:
        blinded_pubkey = crypto_scalarmult_ed25519_noclamp(blind_factor, identity_pubkey)
    except Exception as e:
        logger.error("Ed25519 scalar multiplication failed: %s", e)
        raise ValueError(f"Invalid Ed25519 public key or blind factor: {e}")
    
    return blinded_pubkey


def get_hs_desc_index(blinded_pubkey: bytes, time_period_num: int, 
                       replica: int, srv: bytes) -> bytes:
    """
    Calculate the HSDir index for descriptor storage/lookup.
    
    Per rend-spec-v3 section 2.2.3:
    hs_index(replicanum) = H("store-at-idx" | blinded_pubkey | 
                             INT_8(replicanum) | INT_8(period_length) |
                             INT_8(period_num))
    
    Args:
        blinded_pubkey: 32-byte blinded public key
        time_period_num: Time period number
        replica: Replica number (0 or 1)
        srv: Shared random value from consensus
        
    Returns:
        bytes: 32-byte index value
    """
    # Build the index input
    index_input = (
        b"store-at-idx" +
        blinded_pubkey +
        struct.pack(">Q", replica) +
        struct.pack(">Q", TIME_PERIOD_LENGTH) +
        struct.pack(">Q", time_period_num)
    )
    
    return sha3_256(index_input)


# =============================================================================
# HS-ntor Handshake
# =============================================================================

class HSNtorHandshake:
    """
    Implements the HS-ntor handshake for v3 hidden services.
    
    This is used to establish an encrypted connection through a
    rendezvous point to a v3 hidden service.
    
    Per rend-spec-v3 section 3.3:
    The client creates:
    - Ephemeral x25519 keypair (X, x)
    - Sends INTRODUCE1 containing X
    
    The service responds with:
    - Ephemeral x25519 public key Y
    - Encrypted data using derived keys
    """
    
    def __init__(self, intro_enc_key: bytes, intro_auth_key: bytes,
                 subcredential: bytes):
        """
        Initialize the HS-ntor handshake.
        
        Args:
            intro_enc_key: Introduction point encryption key (x25519 public)
            intro_auth_key: Introduction point auth key (ed25519 public)
            subcredential: Subcredential for the current time period
        """
        self._intro_enc_key = intro_enc_key
        self._intro_auth_key = intro_auth_key
        self._subcredential = subcredential
        
        # Generate ephemeral x25519 keypair
        self._x = curve25519_private()
        self._X = curve25519_public_from_private(self._x)
        
    @property
    def client_pubkey(self) -> bytes:
        """Get the client's ephemeral public key to send in INTRODUCE1."""
        return curve25519_to_bytes(self._X)
    
    def create_onion_key(self) -> Tuple[bytes, bytes]:
        """
        Create the onion key for INTRODUCE1 encryption.
        
        Returns:
            Tuple of (onion_key, encrypted_data_key)
        """
        # EXP(B, x) where B is the intro enc key
        B = curve25519_public_from_bytes(self._intro_enc_key)
        shared = curve25519_get_shared(self._x, B)
        
        # Derive keys
        secret_input = (
            shared +
            self._intro_auth_key +
            curve25519_to_bytes(self._X) +
            self._intro_enc_key +
            HS_NTOR_PROTOID
        )
        
        # Use HKDF to derive encryption keys
        keys = hkdf_sha256(
            sha3_256(secret_input),
            length=64,
            info=HS_NTOR_KEY_EXPAND
        )
        
        enc_key = keys[:32]
        mac_key = keys[32:64]
        
        return enc_key, mac_key
    
    def complete_handshake(self, server_pubkey: bytes, 
                           auth_input: bytes) -> Tuple[bytes, bytes]:
        """
        Complete the HS-ntor handshake after receiving RENDEZVOUS2.
        
        Args:
            server_pubkey: Server's ephemeral x25519 public key (Y)
            auth_input: Additional authentication input
            
        Returns:
            Tuple of (forward_key, backward_key) for circuit encryption
        """
        Y = curve25519_public_from_bytes(server_pubkey)
        B = curve25519_public_from_bytes(self._intro_enc_key)
        
        # Calculate shared secrets
        xy = curve25519_get_shared(self._x, Y)
        xb = curve25519_get_shared(self._x, B)
        
        # Build secret input
        secret_input = (
            xy +
            xb +
            self._intro_auth_key +
            self._intro_enc_key +
            curve25519_to_bytes(self._X) +
            server_pubkey +
            HS_NTOR_PROTOID
        )
        
        # Derive final keys
        keys = hkdf_sha256(
            sha3_256(secret_input),
            length=64,
            info=HS_NTOR_KEY_EXPAND
        )
        
        forward_key = keys[:32]
        backward_key = keys[32:64]
        
        return forward_key, backward_key


# =============================================================================
# Utility Functions
# =============================================================================

def compute_hs_address_checksum(pubkey: bytes, version: int = 3) -> bytes:
    """
    Compute the checksum for a v3 onion address.
    
    Per address-spec section 4:
    checksum = H(".onion checksum" | pubkey | version)[:2]
    
    Args:
        pubkey: 32-byte Ed25519 public key
        version: Address version (default 3)
        
    Returns:
        bytes: 2-byte checksum
    """
    checksum_input = b".onion checksum" + pubkey + bytes([version])
    return sha3_256(checksum_input)[:2]


def verify_hs_address(onion_address: str) -> Tuple[bool, bytes]:
    """
    Verify a v3 onion address and extract the public key.
    
    Args:
        onion_address: 56-character v3 onion address (without .onion)
        
    Returns:
        Tuple of (is_valid, pubkey) where pubkey is 32 bytes if valid
    """
    from base64 import b32decode
    
    try:
        # Decode base32
        decoded = b32decode(onion_address.upper())
        if len(decoded) != 35:  # 32 + 2 + 1
            return False, b""
        
        pubkey = decoded[:32]
        checksum = decoded[32:34]
        version = decoded[34]
        
        if version != 3:
            return False, b""
        
        expected_checksum = compute_hs_address_checksum(pubkey, version)
        if checksum != expected_checksum:
            return False, b""
        
        return True, pubkey
        
    except Exception:
        return False, b""
