#!/usr/bin/env python3
"""
Test HS index computation against Tor reference test vectors.

Test vectors from Tor's test_hs_common.c:test_hs_indexes()
"""

import sys
sys.path.insert(0, 'q:/Projects/torpy')

from torpy.hs_ntor import get_hs_desc_index

# Test vectors from Tor's test_hs_common.c:test_hs_indexes()
# Both use: period_num = 42, pubkey = 32 bytes of 0x42

PERIOD_NUM = 42
REPLICA = 1

# Pubkey is 32 bytes of 0x42
BLINDED_PUBKEY = bytes([0x42] * 32)

# Expected hs_index for replica=1, period=42, pubkey=0x42...
# hs_build_hs_index(1, &pubkey, period_num, hs_index)
EXPECTED_HS_INDEX_HEX = "37e5cbbd56a22823714f18f1623ece5983a0d64c78495a8cfab854245e5f9a8a"

# Expected hsdir_index
# SRV is 32 bytes of 0x43
SRV = bytes([0x43] * 32)
EXPECTED_HSDIR_INDEX_HEX = "db475361014a09965e7e5e4d4a25b8f8d4b8f16cb1d8a7e95eed50249cc1a2d5"


def test_hs_index():
    """Test that our HS index computation matches Tor's test vectors."""
    expected_index = bytes.fromhex(EXPECTED_HS_INDEX_HEX)
    
    print(f"Blinded pubkey: {BLINDED_PUBKEY.hex()}")
    print(f"Period num: {PERIOD_NUM}")
    print(f"Replica: {REPLICA}")
    
    # Compute hs_index using our function
    # Note: our function takes srv as a param but doesn't use it for hs_index
    dummy_srv = bytes(32)
    computed_index = get_hs_desc_index(BLINDED_PUBKEY, PERIOD_NUM, REPLICA, dummy_srv)
    
    print()
    print(f"Computed hs_index: {computed_index.hex()}")
    print(f"Expected hs_index: {expected_index.hex()}")
    print()
    
    if computed_index == expected_index:
        print("✅ HS_INDEX MATCHES!")
        return True
    else:
        print("❌ HS_INDEX MISMATCH!")
        return False


def test_hsdir_index():
    """Test that our HSDir index computation matches Tor's test vectors."""
    from torpy.crypto_common import sha3_256
    import struct
    
    expected_index = bytes.fromhex(EXPECTED_HSDIR_INDEX_HEX)
    
    print()
    print(f"Node identity (pubkey): {BLINDED_PUBKEY.hex()}")
    print(f"SRV: {SRV.hex()}")
    print(f"Period num: {PERIOD_NUM}")
    
    # Compute hsdir_index
    # Per spec: H("node-idx" | identity | srv | INT_8(period_num) | INT_8(period_length))
    # Note: In Tor's test, the order is period_num | period_length
    period_length = 1440  # minutes
    
    data = (
        b"node-idx" +
        BLINDED_PUBKEY +
        SRV +
        struct.pack(">Q", PERIOD_NUM) +
        struct.pack(">Q", period_length)
    )
    computed_index = sha3_256(data)
    
    print()
    print(f"Computed hsdir_index: {computed_index.hex()}")
    print(f"Expected hsdir_index: {expected_index.hex()}")
    print()
    
    if computed_index == expected_index:
        print("✅ HSDIR_INDEX MATCHES!")
        return True
    else:
        print("❌ HSDIR_INDEX MISMATCH!")
        return False


if __name__ == "__main__":
    print("=" * 60)
    print("Testing HS Index Computation Against Tor Test Vectors")
    print("=" * 60)
    print()
    
    hs_ok = test_hs_index()
    hsdir_ok = test_hsdir_index()
    
    print()
    print("=" * 60)
    if hs_ok and hsdir_ok:
        print("ALL TESTS PASSED!")
    else:
        print("SOME TESTS FAILED!")
    print("=" * 60)
