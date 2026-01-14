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

import base64
import hashlib
from hmac import compare_digest

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.hmac import HMAC
from cryptography.hazmat.primitives.ciphers import Cipher
from cryptography.hazmat.primitives.kdf.hkdf import HKDFExpand
from cryptography.hazmat.primitives.asymmetric import dh, padding
from cryptography.hazmat.primitives.ciphers.modes import CTR
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PublicKey, X25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.ciphers.algorithms import AES
from cryptography.exceptions import InvalidSignature

bend = default_backend()


def b64decode(data):
    return base64.b64decode(data + '=' * (len(data) % 4))


def sha1(msg):
    sha = hashes.Hash(hashes.SHA1(), backend=bend)
    sha.update(msg)
    return sha.finalize()


def sha3_256(msg):
    sha = hashes.Hash(hashes.SHA3_256(), backend=bend)
    sha.update(msg)
    return sha.finalize()


def hs_mac(key, msg):
    """
    Hidden service MAC function per rend-spec-v3.
    
    Per spec: MAC(key=k, message=m) = SHA3_256(k_len | k | m)
    where k_len is htonll(len(k)) (8-byte big-endian length of k).
    
    This is different from standard HMAC constructions.
    
    Args:
        key: The MAC key
        msg: The message to authenticate
        
    Returns:
        bytes: 32-byte MAC value
    """
    import struct
    k_len = struct.pack('>Q', len(key))  # 8-byte big-endian
    return sha3_256(k_len + key + msg)


def shake256(msg, length):
    """
    SHAKE-256 extendable output function (XOF).
    
    Per rend-spec-v3, descriptor keys are derived using SHAKE-256 (crypto_xof).
    
    Args:
        msg: Input data to hash
        length: Number of output bytes to generate
        
    Returns:
        bytes: length bytes of SHAKE-256 output
    """
    from cryptography.hazmat.primitives.hashes import SHAKE256
    from cryptography.hazmat.primitives import hashes as crypto_hashes
    
    # Use SHAKE256 XOF
    digest = crypto_hashes.Hash(SHAKE256(length), backend=bend)
    digest.update(msg)
    return digest.finalize()


def hash_stream(name):
    return hashlib.new(name)


def hash_update(hash, msg):
    return hash.update(msg)


def hash_finalize(hash):
    return hash.digest()


def sha1_stream(init_msg=None):
    hash = hashes.Hash(hashes.SHA1(), backend=bend)
    if init_msg:
        sha1_stream_update(hash, init_msg)
    return hash


def sha1_stream_update(hash, msg):
    hash.update(msg)
    return hash


def sha1_stream_clone(hash):
    return hash.copy()


def sha1_stream_finalize(hash):
    return hash.finalize()


def hmac(key, msg):
    hmac = HMAC(key, algorithm=hashes.SHA256(), backend=bend)
    hmac.update(msg)
    return hmac.finalize()


def hkdf_sha256(key, length=16, info=''):
    hkdf = HKDFExpand(algorithm=hashes.SHA256(), length=length, info=info, backend=bend)
    return hkdf.derive(key)


def curve25519_private():
    return X25519PrivateKey.generate()


def curve25519_get_shared(private, public):
    return private.exchange(public)


def curve25519_public_from_private(private):
    return private.public_key()


def curve25519_public_from_bytes(data):
    return X25519PublicKey.from_public_bytes(data)


def curve25519_to_bytes(key):
    if isinstance(key, X25519PublicKey):
        return key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    else:
        return key.private_bytes(
            serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption()
        )


_P = 179769313486231590770839156793787453197860296048756011706444423684197180216158519368947833795864925541502180565485980503646440548199239100050792877003355816639229553136239076508735759914822574862575007425302077447712589550957937778424442426617334727629299387668709205606050270810842907692932019128194467627007  # noqa: E501
_G = 2
_DH_PARAMETERS_NUMBERS = dh.DHParameterNumbers(_P, _G)
_DH_PARAMETERS = _DH_PARAMETERS_NUMBERS.parameters(default_backend())


def dh_private():
    return _DH_PARAMETERS.generate_private_key()


def dh_public(private):
    return private.public_key()


def dh_public_to_bytes(key):
    return key.public_numbers().y.to_bytes(128, 'big')


def dh_public_from_bytes(public_bytes):
    y = int.from_bytes(public_bytes, byteorder='big')
    peer_public_numbers = dh.DHPublicNumbers(y, _DH_PARAMETERS.parameter_numbers())
    return peer_public_numbers.public_key(default_backend())


def dh_shared(private_key, another_public):
    return private_key.exchange(another_public)


def rsa_load_der(public_der_data):
    return serialization.load_der_public_key(public_der_data, backend=bend)


def rsa_load_pem(public_pem_data):
    return serialization.load_pem_public_key(public_pem_data, backend=bend)


def rsa_verify(pubkey, sig, dig):
    dig_size = len(dig)
    sig_int = int(sig.hex(), 16)
    pn = pubkey.public_numbers()
    decoded = pow(sig_int, pn.e, pn.n)
    buf = '%x' % decoded
    if len(buf) % 2:
        buf = '0' + buf
    buf = '00' + buf
    hash_buf = bytes.fromhex(buf)

    pad_type = b'\0\1'
    pad_len = len(hash_buf) - 2 - 1 - dig_size
    cmp_dig = pad_type + b'\xff' * pad_len + b'\0' + dig
    return compare_digest(hash_buf, cmp_dig)


def rsa_encrypt(key, data):
    return key.encrypt(
        data, padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA1()), algorithm=hashes.SHA1(), label=None)
    )


def aes_ctr_encryptor(key, iv=b'\0' * 16):
    return Cipher(AES(key), CTR(iv), backend=bend).encryptor()


def aes_ctr_decryptor(key, iv=b'\0' * 16):
    return Cipher(AES(key), CTR(iv), backend=bend).decryptor()


# Aliases for AES-256 (32-byte key) - same function, key size determines algorithm
aes256_ctr_encryptor = aes_ctr_encryptor
aes256_ctr_decryptor = aes_ctr_decryptor


def aes_update(aes_cipher, data):
    return aes_cipher.update(data)


# =============================================================================
# Ed25519 Signature Functions (for v3 hidden services)
# =============================================================================

def ed25519_generate():
    """
    Generate a new Ed25519 private key.
    
    Returns:
        Ed25519PrivateKey: A new Ed25519 private key
    """
    return Ed25519PrivateKey.generate()


def ed25519_sign(private_key, message):
    """
    Sign a message using Ed25519.
    
    Args:
        private_key: Ed25519PrivateKey
        message: bytes to sign
        
    Returns:
        bytes: 64-byte signature
    """
    return private_key.sign(message)


def ed25519_verify(public_key, signature, message):
    """
    Verify an Ed25519 signature.
    
    Args:
        public_key: Ed25519PublicKey
        signature: 64-byte signature
        message: bytes that were signed
        
    Returns:
        bool: True if signature is valid, False otherwise
    """
    try:
        public_key.verify(signature, message)
        return True
    except InvalidSignature:
        return False


def ed25519_public_from_private(private_key):
    """
    Get the public key from an Ed25519 private key.
    
    Args:
        private_key: Ed25519PrivateKey
        
    Returns:
        Ed25519PublicKey
    """
    return private_key.public_key()


def ed25519_public_from_bytes(data):
    """
    Load an Ed25519 public key from raw bytes.
    
    Args:
        data: 32-byte public key
        
    Returns:
        Ed25519PublicKey
    """
    return Ed25519PublicKey.from_public_bytes(data)


def ed25519_private_from_bytes(data):
    """
    Load an Ed25519 private key from raw bytes.
    
    Args:
        data: 32-byte private key (seed)
        
    Returns:
        Ed25519PrivateKey
    """
    return Ed25519PrivateKey.from_private_bytes(data)


def ed25519_to_bytes(key):
    """
    Serialize an Ed25519 key to raw bytes.
    
    Args:
        key: Ed25519PublicKey or Ed25519PrivateKey
        
    Returns:
        bytes: 32-byte key data
    """
    if isinstance(key, Ed25519PublicKey):
        return key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    else:
        return key.private_bytes(
            serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption()
        )


def ed25519_public_key_to_bytes(public_key):
    """
    Serialize an Ed25519 public key to raw bytes.
    Alias for ed25519_to_bytes for public keys.
    
    Args:
        public_key: Ed25519PublicKey
        
    Returns:
        bytes: 32-byte public key
    """
    return public_key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
