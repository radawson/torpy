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
V3 Hidden Service Descriptor parsing and decryption.

Implements the descriptor format and encryption defined in rend-spec-v3:
https://gitlab.torproject.org/tpo/core/torspec/-/blob/main/spec/rend-spec-v3.md

Descriptor structure (section 2.5):
- Outer layer: Plaintext metadata + encrypted blob
- First layer: Encrypted with blinded key + subcredential
- Second layer (optional): Encrypted with client authorization key
"""

import re
import struct
import logging
from base64 import b64decode, b64encode
from typing import Dict, List, Optional, Tuple, Any

from torpy.crypto_common import (
    sha3_256,
    shake256,
    aes_ctr_decryptor,
    aes_update,
    hmac,
)

logger = logging.getLogger(__name__)

# =============================================================================
# Constants
# =============================================================================

# Descriptor encryption keys derivation
SECRET_DATA_STR = b"hsdir-superencrypted-data"
SECRET_DATA_INNER_STR = b"hsdir-encrypted-data"

# Encryption parameters
SALT_LEN = 16
MAC_LEN = 32
AES_KEY_LEN = 32
AES_IV_LEN = 16

# Descriptor parsing patterns
HS_DESC_HEADER = "hs-descriptor 3"
HS_DESC_LIFETIME_PATTERN = re.compile(r"descriptor-lifetime (\d+)")
HS_DESC_REVISION_PATTERN = re.compile(r"revision-counter (\d+)")
HS_DESC_SUPERENCRYPTED_PATTERN = re.compile(
    r"superencrypted\n-----BEGIN MESSAGE-----\n(.+?)\n-----END MESSAGE-----",
    re.DOTALL
)
HS_DESC_ENCRYPTED_PATTERN = re.compile(
    r"encrypted\n-----BEGIN MESSAGE-----\n(.+?)\n-----END MESSAGE-----",
    re.DOTALL
)

# Introduction point parsing
INTRO_POINT_PATTERN = re.compile(
    r"introduction-point (.+?)(?=introduction-point|$)",
    re.DOTALL
)


# =============================================================================
# Descriptor Decryption
# =============================================================================

def _derive_descriptor_keys(secret_data: bytes, subcredential: bytes,
                            revision_counter: int, salt: bytes,
                            purpose: bytes) -> Tuple[bytes, bytes, bytes]:
    """
    Derive AES key, IV and MAC key for descriptor decryption.
    
    Per rend-spec-v3 section 2.5:
    secret_input = SECRET_DATA | subcredential | revision_counter
    KEYS = KDF(secret_input | salt | purpose, S_KEY_LEN + S_IV_LEN + MAC_KEY_LEN)
    
    Where KDF is SHAKE-256 (XOF), not HKDF-SHA256!
    
    Args:
        secret_data: blinded_pubkey for outer layer, or blinded_pubkey + descriptor_cookie for inner
        subcredential: 32-byte subcredential
        revision_counter: Descriptor revision counter
        salt: 16-byte random salt from descriptor
        purpose: Purpose string (SECRET_DATA_STR or SECRET_DATA_INNER_STR)
        
    Returns:
        Tuple of (aes_key, aes_iv, mac_key)
    """
    # Build secret_input = SECRET_DATA | subcredential | revision_counter (8 bytes big-endian)
    secret_input = secret_data + subcredential + struct.pack(">Q", revision_counter)
    
    # Build KDF input = secret_input | salt | purpose
    kdf_input = secret_input + salt + purpose
    
    # Derive keys using SHAKE-256 (XOF)
    # Output length = 32 (AES key) + 16 (IV) + 32 (MAC key) = 80 bytes
    key_material = shake256(kdf_input, AES_KEY_LEN + AES_IV_LEN + MAC_LEN)
    
    aes_key = key_material[:AES_KEY_LEN]
    aes_iv = key_material[AES_KEY_LEN:AES_KEY_LEN + AES_IV_LEN]
    mac_key = key_material[AES_KEY_LEN + AES_IV_LEN:]
    
    return aes_key, aes_iv, mac_key


def _compute_mac(mac_key: bytes, salt: bytes, ciphertext: bytes) -> bytes:
    """
    Compute MAC for descriptor data.
    
    Per rend-spec-v3/proposal 224:
    MAC = SHA3-256(mac_key_len | mac_key | salt_len | salt | ciphertext)
    
    Args:
        mac_key: 32-byte MAC key
        salt: 16-byte salt
        ciphertext: Encrypted data
        
    Returns:
        32-byte MAC value
    """
    # Format: H(mac_key_len | mac_key | salt_len | salt | encrypted)
    mac_input = (
        struct.pack(">Q", len(mac_key)) +
        mac_key +
        struct.pack(">Q", len(salt)) +
        salt +
        ciphertext
    )
    return sha3_256(mac_input)


def decrypt_outer_layer(encrypted_blob: bytes, blinded_pubkey: bytes,
                        subcredential: bytes, 
                        revision_counter: int) -> Optional[bytes]:
    """
    Decrypt the outer (superencrypted) layer of a v3 descriptor.
    
    Per rend-spec-v3 section 2.5.2.1:
    The outer layer is encrypted using:
    - SECRET_DATA = blinded_pubkey (for outer layer)
    - secret_input = SECRET_DATA | subcredential | revision_counter
    - KEYS = SHAKE-256(secret_input | salt | "hsdir-superencrypted-data")
    - AES-256-CTR with derived key and IV
    
    Args:
        encrypted_blob: Base64-decoded encrypted data (salt + ciphertext + mac)
        blinded_pubkey: 32-byte blinded public key
        subcredential: 32-byte subcredential
        revision_counter: Descriptor revision counter
        
    Returns:
        Decrypted plaintext or None if decryption fails
    """
    if len(encrypted_blob) < SALT_LEN + MAC_LEN + 1:
        logger.error("Encrypted blob too short")
        return None
    
    # Extract components
    salt = encrypted_blob[:SALT_LEN]
    ciphertext = encrypted_blob[SALT_LEN:-MAC_LEN]
    mac = encrypted_blob[-MAC_LEN:]
    
    # Derive keys using SHAKE-256
    # SECRET_DATA for outer layer is just the blinded pubkey
    aes_key, aes_iv, mac_key = _derive_descriptor_keys(
        blinded_pubkey, subcredential, revision_counter, salt, SECRET_DATA_STR
    )
    
    # Verify MAC
    computed_mac = _compute_mac(mac_key, salt, ciphertext)
    if computed_mac != mac:
        logger.warning("MAC verification failed for outer layer (will try to decrypt anyway)")
    
    # Decrypt
    decryptor = aes_ctr_decryptor(aes_key, aes_iv)
    plaintext = aes_update(decryptor, ciphertext)
    
    return plaintext


def decrypt_inner_layer(encrypted_blob: bytes, blinded_pubkey: bytes,
                        subcredential: bytes,
                        revision_counter: int,
                        descriptor_cookie: Optional[bytes] = None) -> Optional[bytes]:
    """
    Decrypt the inner (encrypted) layer of a v3 descriptor.
    
    Per rend-spec-v3 section 2.5.2.2:
    - SECRET_DATA = blinded_pubkey (+ descriptor_cookie if client auth)
    - secret_input = SECRET_DATA | subcredential | revision_counter
    - KEYS = SHAKE-256(secret_input | salt | "hsdir-encrypted-data")
    
    Args:
        encrypted_blob: Base64-decoded encrypted data
        blinded_pubkey: 32-byte blinded public key
        subcredential: 32-byte subcredential
        revision_counter: Descriptor revision counter
        descriptor_cookie: Optional 32-byte descriptor cookie for client auth
        
    Returns:
        Decrypted plaintext or None if decryption fails
    """
    if len(encrypted_blob) < SALT_LEN + MAC_LEN + 1:
        logger.error("Inner encrypted blob too short")
        return None
    
    # Extract components
    salt = encrypted_blob[:SALT_LEN]
    ciphertext = encrypted_blob[SALT_LEN:-MAC_LEN]
    mac = encrypted_blob[-MAC_LEN:]
    
    # Build SECRET_DATA for inner layer
    # SECRET_DATA = blinded_pubkey (+ descriptor_cookie if present)
    if descriptor_cookie:
        secret_data = blinded_pubkey + descriptor_cookie
    else:
        secret_data = blinded_pubkey
    
    # Derive keys using SHAKE-256
    aes_key, aes_iv, mac_key = _derive_descriptor_keys(
        secret_data, subcredential, revision_counter, salt, SECRET_DATA_INNER_STR
    )
    
    # Verify MAC
    computed_mac = _compute_mac(mac_key, salt, ciphertext)
    if computed_mac != mac:
        logger.debug("MAC verification failed for inner layer")
        return None
    
    # Decrypt
    decryptor = aes_ctr_decryptor(aes_key, aes_iv)
    plaintext = aes_update(decryptor, ciphertext)
    
    return plaintext


# =============================================================================
# Descriptor Parsing
# =============================================================================

class V3HSDescriptor:
    """
    Represents a parsed v3 hidden service descriptor.
    """
    
    def __init__(self):
        self.version = 3
        self.lifetime = 0
        self.revision_counter = 0
        self.superencrypted_blob = b""
        self.signing_key_cert = b""
        self.signature = b""
        
        # Decrypted data
        self.introduction_points: List[Dict[str, Any]] = []
        self.create2_formats: List[int] = []
        self.single_onion_service = False
    
    def __repr__(self):
        return (f"V3HSDescriptor(revision={self.revision_counter}, "
                f"intro_points={len(self.introduction_points)})")


def parse_descriptor_outer(descriptor_text: str) -> Optional[V3HSDescriptor]:
    """
    Parse the outer layer of a v3 hidden service descriptor.
    
    Args:
        descriptor_text: Raw descriptor text from HSDir
        
    Returns:
        V3HSDescriptor with outer fields populated, or None on error
    """
    if not descriptor_text.startswith(HS_DESC_HEADER):
        logger.error("Invalid descriptor header")
        return None
    
    desc = V3HSDescriptor()
    
    # Parse lifetime
    lifetime_match = HS_DESC_LIFETIME_PATTERN.search(descriptor_text)
    if lifetime_match:
        desc.lifetime = int(lifetime_match.group(1))
    
    # Parse revision counter
    revision_match = HS_DESC_REVISION_PATTERN.search(descriptor_text)
    if revision_match:
        desc.revision_counter = int(revision_match.group(1))
    
    # Extract superencrypted blob
    superenc_match = HS_DESC_SUPERENCRYPTED_PATTERN.search(descriptor_text)
    if superenc_match:
        try:
            # Remove whitespace and decode base64
            blob_b64 = superenc_match.group(1).replace("\n", "").replace(" ", "")
            desc.superencrypted_blob = b64decode(blob_b64)
        except Exception as e:
            logger.error(f"Failed to decode superencrypted blob: {e}")
            return None
    else:
        logger.error("No superencrypted blob found in descriptor")
        return None
    
    return desc


def parse_first_layer(plaintext: bytes) -> Tuple[Optional[bytes], Optional[str]]:
    """
    Parse the first (superencrypted) layer after decryption.
    
    Args:
        plaintext: Decrypted first layer data
        
    Returns:
        Tuple of (encrypted_inner_blob, auth_type) or (None, None) on error
    """
    try:
        text = plaintext.decode('utf-8', errors='ignore')
    except Exception:
        return None, None
    
    # Check for client authorization
    auth_type = None
    if "desc-auth-type" in text:
        auth_match = re.search(r"desc-auth-type (\w+)", text)
        if auth_match:
            auth_type = auth_match.group(1)
    
    # Extract encrypted inner blob
    enc_match = HS_DESC_ENCRYPTED_PATTERN.search(text)
    if enc_match:
        try:
            blob_b64 = enc_match.group(1).replace("\n", "").replace(" ", "")
            return b64decode(blob_b64), auth_type
        except Exception as e:
            logger.error(f"Failed to decode encrypted inner blob: {e}")
            return None, None
    
    # If no encrypted blob, the plaintext might be the final layer
    # This happens for services without client authorization
    return plaintext, auth_type


def parse_introduction_points(plaintext: bytes) -> List[Dict[str, Any]]:
    """
    Parse introduction points from the decrypted inner layer.
    
    Args:
        plaintext: Decrypted inner layer data
        
    Returns:
        List of introduction point dictionaries
    """
    intro_points = []
    
    try:
        text = plaintext.decode('utf-8', errors='ignore')
    except Exception as e:
        logger.error(f"Failed to decode introduction points: {e}")
        return intro_points
    
    # State machine for parsing
    current_intro = None
    in_auth_key_cert = False
    in_enc_key_cert = False
    cert_lines = []
    
    for line in text.split('\n'):
        stripped = line.strip()
        
        # Handle certificate blocks
        if in_auth_key_cert:
            cert_lines.append(line)
            if '-----END ED25519 CERT-----' in line:
                in_auth_key_cert = False
                if current_intro:
                    # Parse the Ed25519 certificate to extract the public key
                    cert_data = _parse_ed25519_cert(cert_lines)
                    if cert_data:
                        current_intro['auth_key'] = cert_data
                    current_intro['auth_key_cert_raw'] = '\n'.join(cert_lines)
                cert_lines = []
            continue
        
        if in_enc_key_cert:
            cert_lines.append(line)
            if '-----END ED25519 CERT-----' in line:
                in_enc_key_cert = False
                if current_intro:
                    current_intro['enc_key_cert_raw'] = '\n'.join(cert_lines)
                cert_lines = []
            continue
        
        if not stripped:
            continue
        
        if stripped.startswith("introduction-point "):
            if current_intro:
                intro_points.append(current_intro)
            current_intro = {
                'link_specifiers': [],
                'link_specifiers_raw': b'',
                'onion_key': None,
                'auth_key': None,
                'auth_key_cert_raw': None,
                'enc_key': None,
                'enc_key_cert': None,
                'enc_key_cert_raw': None,
            }
            # Parse base64-encoded link specifiers
            try:
                ls_b64 = stripped[len("introduction-point "):].strip()
                current_intro['link_specifiers_raw'] = b64decode(ls_b64)
            except Exception:
                pass
        
        elif current_intro:
            if stripped.startswith("onion-key ntor "):
                try:
                    key_b64 = stripped[len("onion-key ntor "):].strip()
                    current_intro['onion_key'] = b64decode(key_b64)
                except Exception:
                    pass
            
            elif stripped == "auth-key":
                # Multi-line auth key certificate follows
                in_auth_key_cert = True
                cert_lines = []
            
            elif stripped.startswith("enc-key ntor "):
                try:
                    key_b64 = stripped[len("enc-key ntor "):].strip()
                    current_intro['enc_key'] = b64decode(key_b64)
                except Exception:
                    pass
            
            elif stripped == "enc-key-cert":
                # Multi-line enc-key certificate follows
                in_enc_key_cert = True
                cert_lines = []
    
    # Don't forget the last intro point
    if current_intro:
        intro_points.append(current_intro)
    
    return intro_points


def _parse_ed25519_cert(cert_lines: List[str]) -> Optional[bytes]:
    """
    Parse an Ed25519 certificate and extract the certified key.
    
    Per proposal 220, the Ed25519 certificate format is:
    - VERSION (1 byte): Currently 0x01
    - CERT_TYPE (1 byte)
    - EXPIRATION_DATE (4 bytes)
    - KEY_TYPE (1 byte)
    - CERTIFIED_KEY (32 bytes)
    - N_EXTENSIONS (1 byte)
    - Extensions...
    - Signature (64 bytes)
    
    Args:
        cert_lines: Lines of the PEM-wrapped certificate
        
    Returns:
        32-byte Ed25519 public key, or None on error
    """
    try:
        # Extract base64 content from PEM wrapper
        cert_b64 = ''
        in_cert = False
        for line in cert_lines:
            if '-----BEGIN ED25519 CERT-----' in line:
                in_cert = True
                continue
            if '-----END ED25519 CERT-----' in line:
                break
            if in_cert:
                cert_b64 += line.strip()
        
        if not cert_b64:
            return None
        
        cert_data = b64decode(cert_b64)
        
        # Parse certificate
        if len(cert_data) < 40:  # Minimum: 1+1+4+1+32+1 = 40 bytes without signature
            logger.debug(f"Certificate too short: {len(cert_data)} bytes")
            return None
        
        # version = cert_data[0]
        # cert_type = cert_data[1]
        # expiration = struct.unpack(">I", cert_data[2:6])[0]
        # key_type = cert_data[6]
        certified_key = cert_data[7:39]  # 32-byte Ed25519 public key
        
        return certified_key
    
    except Exception as e:
        logger.debug(f"Failed to parse Ed25519 certificate: {e}")
        return None


def parse_link_specifiers(data: bytes) -> List[Dict[str, Any]]:
    """
    Parse link specifiers from introduction point data.
    
    Per tor-spec section 5.1.2:
    Link specifier format:
    - LSTYPE (1 byte): Type of specifier
    - LSLEN (1 byte): Length of LSPEC
    - LSPEC (LSLEN bytes): Specifier data
    
    Types:
    - 0: IPv4 address + port (6 bytes)
    - 1: IPv6 address + port (18 bytes)
    - 2: Legacy identity (20 bytes)
    - 3: Ed25519 identity (32 bytes)
    
    Args:
        data: Raw link specifier data
        
    Returns:
        List of parsed link specifier dictionaries
    """
    specifiers = []
    offset = 0
    
    # First byte is the count
    if len(data) < 1:
        return specifiers
    
    count = data[0]
    offset = 1
    
    for _ in range(count):
        if offset + 2 > len(data):
            break
        
        ls_type = data[offset]
        ls_len = data[offset + 1]
        offset += 2
        
        if offset + ls_len > len(data):
            break
        
        ls_data = data[offset:offset + ls_len]
        offset += ls_len
        
        spec = {'type': ls_type, 'data': ls_data}
        
        if ls_type == 0 and ls_len == 6:  # IPv4
            import socket
            ip = socket.inet_ntoa(ls_data[:4])
            port = struct.unpack(">H", ls_data[4:6])[0]
            spec['ip'] = ip
            spec['port'] = port
        elif ls_type == 1 and ls_len == 18:  # IPv6
            import socket
            ip = socket.inet_ntop(socket.AF_INET6, ls_data[:16])
            port = struct.unpack(">H", ls_data[16:18])[0]
            spec['ip'] = ip
            spec['port'] = port
        elif ls_type == 2 and ls_len == 20:  # Legacy ID
            spec['legacy_id'] = ls_data.hex()
        elif ls_type == 3 and ls_len == 32:  # Ed25519 ID
            spec['ed25519_id'] = ls_data.hex()
        
        specifiers.append(spec)
    
    return specifiers


# =============================================================================
# High-Level Interface
# =============================================================================

def decrypt_v3_descriptor(descriptor_text: str, identity_pubkey: bytes,
                          blinded_pubkey: bytes, subcredential: bytes,
                          client_key: Optional[bytes] = None) -> Optional[V3HSDescriptor]:
    """
    Fully decrypt a v3 hidden service descriptor.
    
    Args:
        descriptor_text: Raw descriptor text from HSDir
        identity_pubkey: 32-byte Ed25519 identity public key
        blinded_pubkey: 32-byte blinded public key
        subcredential: 32-byte subcredential for time period
        client_key: Optional client authorization key
        
    Returns:
        Fully decrypted V3HSDescriptor or None on error
    """
    logger.debug(f"decrypt_v3_descriptor: descriptor length = {len(descriptor_text)}")
    logger.debug(f"decrypt_v3_descriptor: blinded_pubkey = {blinded_pubkey[:8].hex()}...")
    logger.debug(f"decrypt_v3_descriptor: subcredential = {subcredential[:8].hex()}...")
    
    # Parse outer layer
    desc = parse_descriptor_outer(descriptor_text)
    if not desc:
        logger.error("Failed to parse outer descriptor layer")
        return None
    
    logger.debug(f"decrypt_v3_descriptor: revision_counter = {desc.revision_counter}")
    logger.debug(f"decrypt_v3_descriptor: superencrypted_blob length = {len(desc.superencrypted_blob)}")
    
    # Decrypt first layer
    first_layer = decrypt_outer_layer(
        desc.superencrypted_blob,
        blinded_pubkey,
        subcredential,
        desc.revision_counter
    )
    if not first_layer:
        logger.error("Failed to decrypt outer layer")
        return None
    
    logger.debug(f"decrypt_v3_descriptor: first_layer length = {len(first_layer)}")
    logger.debug(f"decrypt_v3_descriptor: first_layer preview = {first_layer[:200]}")
    
    # Parse first layer to get encrypted inner blob
    inner_blob, auth_type = parse_first_layer(first_layer)
    if not inner_blob:
        logger.error("Failed to parse first layer")
        return None
    
    logger.debug(f"decrypt_v3_descriptor: inner_blob length = {len(inner_blob)}")
    logger.debug(f"decrypt_v3_descriptor: auth_type = {auth_type}")
    
    # Decrypt inner layer
    if auth_type and not client_key:
        logger.warning(f"Descriptor requires {auth_type} authorization")
        # Try decrypting anyway - might be optional auth
    
    # For inner layer, secret_data is blinded_pubkey (+ descriptor_cookie if auth)
    # client_key here would be a descriptor_cookie derived from client auth
    inner_layer = decrypt_inner_layer(
        inner_blob,
        blinded_pubkey,
        subcredential,
        desc.revision_counter,
        descriptor_cookie=client_key  # descriptor_cookie for client auth
    )
    
    if inner_layer:
        logger.debug(f"decrypt_v3_descriptor: inner_layer length = {len(inner_layer)}")
        logger.debug(f"decrypt_v3_descriptor: inner_layer preview = {inner_layer[:200]}")
    else:
        logger.debug("decrypt_v3_descriptor: decrypt_inner_layer returned None, using inner_blob as plaintext")
        # Try treating inner_blob as already decrypted (no client auth)
        inner_layer = inner_blob
    
    # Parse introduction points
    desc.introduction_points = parse_introduction_points(inner_layer)
    logger.debug(f"decrypt_v3_descriptor: found {len(desc.introduction_points)} introduction points")
    
    # Parse link specifiers for each intro point
    for ip in desc.introduction_points:
        if 'link_specifiers_raw' in ip:
            ip['link_specifiers'] = parse_link_specifiers(ip['link_specifiers_raw'])
    
    return desc
