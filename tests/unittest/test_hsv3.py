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

"""Tests for v3 hidden service support."""

import struct
import pytest

from torpy.hiddenservice import HiddenService
from torpy.hs_ntor import (
    get_time_period_num,
    get_time_period_length,
    build_credential,
    build_subcredential,
    derive_blinded_pubkey,
    verify_hs_address,
    compute_hs_address_checksum,
    HSNtorHandshake,
)
from torpy.hs_descriptor import (
    parse_link_specifiers,
    parse_descriptor_outer,
    V3HSDescriptor,
)
from torpy.crypto_common import (
    ed25519_generate,
    ed25519_sign,
    ed25519_verify,
    ed25519_public_from_private,
    ed25519_to_bytes,
    curve25519_private,
    curve25519_public_from_private,
    curve25519_to_bytes,
)


class TestEd25519Crypto:
    """Tests for Ed25519 cryptographic primitives."""

    def test_key_generation(self):
        """Test Ed25519 key generation."""
        private_key = ed25519_generate()
        public_key = ed25519_public_from_private(private_key)
        assert public_key is not None

    def test_key_serialization(self):
        """Test Ed25519 key serialization."""
        private_key = ed25519_generate()
        public_key = ed25519_public_from_private(private_key)
        
        pub_bytes = ed25519_to_bytes(public_key)
        assert len(pub_bytes) == 32

    def test_sign_verify(self):
        """Test Ed25519 signature creation and verification."""
        private_key = ed25519_generate()
        public_key = ed25519_public_from_private(private_key)
        
        message = b"Test message for v3 hidden services"
        signature = ed25519_sign(private_key, message)
        
        assert len(signature) == 64
        assert ed25519_verify(public_key, signature, message)

    def test_verify_invalid_signature(self):
        """Test that invalid signatures are rejected."""
        private_key = ed25519_generate()
        public_key = ed25519_public_from_private(private_key)
        
        message = b"Original message"
        signature = ed25519_sign(private_key, message)
        
        # Verify with wrong message should fail
        assert not ed25519_verify(public_key, signature, b"Wrong message")


class TestTimePeriod:
    """Tests for time period calculations."""

    def test_time_period_num(self):
        """Test time period number calculation."""
        tp = get_time_period_num()
        assert tp > 0

    def test_time_period_length(self):
        """Test time period length."""
        length = get_time_period_length()
        assert length == 1440 * 60  # 24 hours in seconds

    def test_time_period_deterministic(self):
        """Test that time period is deterministic for same timestamp."""
        import time
        ts = int(time.time())
        tp1 = get_time_period_num(ts)
        tp2 = get_time_period_num(ts)
        assert tp1 == tp2


class TestV3AddressValidation:
    """Tests for v3 onion address validation."""

    def test_valid_address(self):
        """Test validation of a known valid v3 address."""
        # DuckDuckGo's v3 address
        addr = "duckduckgogg42xjoc72x3sjasowoarfbgcmvfimaftt6twagswzczad"
        is_valid, pubkey = verify_hs_address(addr)
        assert is_valid
        assert len(pubkey) == 32

    def test_invalid_address_wrong_length(self):
        """Test rejection of address with wrong length."""
        addr = "tooshort"
        is_valid, pubkey = verify_hs_address(addr)
        assert not is_valid
        assert pubkey == b""

    def test_checksum_computation(self):
        """Test checksum computation."""
        pubkey = b'\x00' * 32
        checksum = compute_hs_address_checksum(pubkey, version=3)
        assert len(checksum) == 2


class TestBlindedKeyDerivation:
    """Tests for blinded key derivation."""

    def test_blinded_key_length(self):
        """Test that blinded keys are 32 bytes."""
        pubkey = b'\x01' * 32
        tp = get_time_period_num()
        blinded = derive_blinded_pubkey(pubkey, tp)
        assert len(blinded) == 32

    def test_blinded_key_deterministic(self):
        """Test that blinded key derivation is deterministic."""
        pubkey = b'\x02' * 32
        tp = get_time_period_num()
        
        blinded1 = derive_blinded_pubkey(pubkey, tp)
        blinded2 = derive_blinded_pubkey(pubkey, tp)
        assert blinded1 == blinded2

    def test_blinded_key_different_periods(self):
        """Test that blinded keys differ for different time periods."""
        pubkey = b'\x03' * 32
        tp = get_time_period_num()
        
        blinded1 = derive_blinded_pubkey(pubkey, tp)
        blinded2 = derive_blinded_pubkey(pubkey, tp + 1)
        assert blinded1 != blinded2


class TestCredentials:
    """Tests for credential and subcredential derivation."""

    def test_credential_length(self):
        """Test credential is 32 bytes."""
        pubkey = b'\x04' * 32
        cred = build_credential(pubkey)
        assert len(cred) == 32

    def test_subcredential_length(self):
        """Test subcredential is 32 bytes."""
        pubkey = b'\x05' * 32
        blinded = b'\x06' * 32
        subcred = build_subcredential(pubkey, blinded)
        assert len(subcred) == 32

    def test_credential_deterministic(self):
        """Test credential derivation is deterministic."""
        pubkey = b'\x07' * 32
        cred1 = build_credential(pubkey)
        cred2 = build_credential(pubkey)
        assert cred1 == cred2


class TestHiddenServiceV3:
    """Tests for v3 HiddenService class."""

    def test_v3_address_detection(self):
        """Test that v3 addresses are correctly detected."""
        addr = "duckduckgogg42xjoc72x3sjasowoarfbgcmvfimaftt6twagswzczad.onion"
        hs = HiddenService(addr)
        assert hs.version == 3
        assert hs.is_v3

    def test_v2_address_detection(self):
        """Test that v2 addresses are correctly detected."""
        addr = "facebookcorewwwi.onion"
        hs = HiddenService(addr)
        assert hs.version == 2
        assert not hs.is_v3

    def test_v3_identity_pubkey(self):
        """Test v3 identity pubkey extraction."""
        addr = "duckduckgogg42xjoc72x3sjasowoarfbgcmvfimaftt6twagswzczad.onion"
        hs = HiddenService(addr)
        assert hs.identity_pubkey is not None
        assert len(hs.identity_pubkey) == 32

    def test_v3_blinded_pubkey(self):
        """Test v3 blinded pubkey derivation via HiddenService."""
        addr = "duckduckgogg42xjoc72x3sjasowoarfbgcmvfimaftt6twagswzczad.onion"
        hs = HiddenService(addr)
        blinded = hs.get_blinded_pubkey()
        assert len(blinded) == 32

    def test_v3_subcredential(self):
        """Test v3 subcredential derivation via HiddenService."""
        addr = "duckduckgogg42xjoc72x3sjasowoarfbgcmvfimaftt6twagswzczad.onion"
        hs = HiddenService(addr)
        subcred = hs.get_subcredential()
        assert len(subcred) == 32

    def test_v3_descriptor_id(self):
        """Test v3 descriptor ID derivation via HiddenService."""
        addr = "duckduckgogg42xjoc72x3sjasowoarfbgcmvfimaftt6twagswzczad.onion"
        hs = HiddenService(addr)
        desc_id = hs.get_descriptor_id_v3()
        assert len(desc_id) == 32

    def test_v2_no_blinded_pubkey(self):
        """Test that v2 addresses don't support blinded pubkey."""
        addr = "facebookcorewwwi.onion"
        hs = HiddenService(addr)
        with pytest.raises(RuntimeError):
            hs.get_blinded_pubkey()


class TestLinkSpecifiers:
    """Tests for link specifier parsing."""

    def test_parse_ipv4_specifier(self):
        """Test parsing IPv4 link specifier."""
        # Build test data: 1 IPv4 specifier (127.0.0.1:9001)
        data = bytes([1])  # count = 1
        data += bytes([0, 6])  # type=IPv4, len=6
        data += bytes([127, 0, 0, 1]) + struct.pack('>H', 9001)
        
        specs = parse_link_specifiers(data)
        assert len(specs) == 1
        assert specs[0]['type'] == 0
        assert specs[0]['ip'] == '127.0.0.1'
        assert specs[0]['port'] == 9001

    def test_parse_legacy_id_specifier(self):
        """Test parsing legacy identity specifier."""
        # Build test data: 1 legacy ID specifier
        legacy_id = b'\xaa' * 20
        data = bytes([1])  # count = 1
        data += bytes([2, 20])  # type=legacy_id, len=20
        data += legacy_id
        
        specs = parse_link_specifiers(data)
        assert len(specs) == 1
        assert specs[0]['type'] == 2
        assert specs[0]['legacy_id'] == legacy_id.hex()

    def test_parse_multiple_specifiers(self):
        """Test parsing multiple link specifiers."""
        # Build test data: 2 specifiers
        data = bytes([2])  # count = 2
        # IPv4
        data += bytes([0, 6])
        data += bytes([192, 168, 1, 1]) + struct.pack('>H', 443)
        # Legacy ID
        data += bytes([2, 20])
        data += b'\xbb' * 20
        
        specs = parse_link_specifiers(data)
        assert len(specs) == 2


class TestHSNtorHandshake:
    """Tests for HS-ntor handshake."""

    def test_handshake_initialization(self):
        """Test HS-ntor handshake initialization."""
        intro_enc_key = curve25519_to_bytes(
            curve25519_public_from_private(curve25519_private())
        )
        intro_auth_key = ed25519_to_bytes(
            ed25519_public_from_private(ed25519_generate())
        )
        subcred = b'\x00' * 32
        
        handshake = HSNtorHandshake(intro_enc_key, intro_auth_key, subcred)
        assert handshake is not None

    def test_client_pubkey_generation(self):
        """Test that client pubkey is generated."""
        intro_enc_key = curve25519_to_bytes(
            curve25519_public_from_private(curve25519_private())
        )
        intro_auth_key = ed25519_to_bytes(
            ed25519_public_from_private(ed25519_generate())
        )
        subcred = b'\x00' * 32
        
        handshake = HSNtorHandshake(intro_enc_key, intro_auth_key, subcred)
        client_pub = handshake.client_pubkey
        assert len(client_pub) == 32


class TestV3Cells:
    """Tests for v3 relay cells."""

    def test_introduce1_v3_import(self):
        """Test that CellRelayIntroduce1V3 can be imported."""
        from torpy.cells import CellRelayIntroduce1V3
        assert CellRelayIntroduce1V3.NUM == 34

    def test_introduce2_import(self):
        """Test that CellRelayIntroduce2 can be imported."""
        from torpy.cells import CellRelayIntroduce2
        assert CellRelayIntroduce2.NUM == 35

    def test_rendezvous1_import(self):
        """Test that CellRelayRendezvous1 can be imported."""
        from torpy.cells import CellRelayRendezvous1
        assert CellRelayRendezvous1.NUM == 36

    def test_introduce1_v3_serialization(self):
        """Test CellRelayIntroduce1V3 serialization."""
        from torpy.cells import CellRelayIntroduce1V3
        
        cell = CellRelayIntroduce1V3(
            legacy_key_id=b'\x00' * 20,
            auth_key=b'\x01' * 32,
            encrypted_data=b'\x02' * 100,
            circuit_id=1
        )
        
        payload = cell._serialize_payload()
        assert len(payload) > 0
        # Should contain: 20 + 1 + 2 + 32 + 1 + 100 = 156 bytes
        assert len(payload) == 156

    def test_rendezvous1_serialization(self):
        """Test CellRelayRendezvous1 serialization."""
        from torpy.cells import CellRelayRendezvous1
        
        cell = CellRelayRendezvous1(
            rendezvous_cookie=b'\xaa' * 20,
            handshake_info=b'\xbb' * 64,
            circuit_id=1
        )
        
        payload = cell._serialize_payload()
        assert len(payload) == 20 + 64
