#!/usr/bin/env python3
"""
Test blinded key derivation against Tor reference test vectors.

Test vectors from Tor's test_hs_common.c:test_blinding_basics()
"""

import sys
sys.path.insert(0, 'q:/Projects/torpy')

from torpy.hs_ntor import (
    derive_blinded_pubkey,
    build_subcredential,
    TIME_PERIOD_LENGTH,
)
from torpy.crypto_common import sha3_256

# Test vectors from Tor's test_hs_common.c
TIME_PERIOD = 1234

# Identity public key (hex)
IDENTITY_PUBKEY_HEX = "833990B085C1A688C1D4C8B1F6B56AFAF5A2ECA674449E1D704F83765CCB7BC6"

# Expected blinded public key (hex)
EXPECTED_BLINDED_PUBKEY_HEX = "3A50BF210E8F9EE955AE0014F7A6917FB65EBF098A86305ABB508D1A7291B6D5"

# Expected subcredential (hex)
EXPECTED_SUBCRED_HEX = "635D55907816E8D76398A675A50B1C2F3E36B42A5CA77BA3A0441285161AE07D"


def test_blinded_pubkey():
    """Test that our blinded pubkey derivation matches Tor's test vectors."""
    identity_pubkey = bytes.fromhex(IDENTITY_PUBKEY_HEX)
    expected_blinded = bytes.fromhex(EXPECTED_BLINDED_PUBKEY_HEX)
    
    print(f"TIME_PERIOD_LENGTH module constant: {TIME_PERIOD_LENGTH}")
    print(f"TIME_PERIOD_LENGTH in minutes: {TIME_PERIOD_LENGTH // 60}")
    print()
    print(f"Identity pubkey: {identity_pubkey.hex()}")
    print(f"Time period: {TIME_PERIOD}")
    
    # Derive blinded pubkey
    blinded_pubkey = derive_blinded_pubkey(identity_pubkey, TIME_PERIOD)
    
    print()
    print(f"Computed blinded pubkey: {blinded_pubkey.hex()}")
    print(f"Expected blinded pubkey: {expected_blinded.hex()}")
    print()
    
    if blinded_pubkey == expected_blinded:
        print("✅ BLINDED PUBKEY MATCHES!")
        return True
    else:
        print("❌ BLINDED PUBKEY MISMATCH!")
        return False


def test_subcredential():
    """Test that our subcredential derivation matches Tor's test vectors."""
    identity_pubkey = bytes.fromhex(IDENTITY_PUBKEY_HEX)
    expected_subcred = bytes.fromhex(EXPECTED_SUBCRED_HEX)
    
    # First derive blinded pubkey
    blinded_pubkey = derive_blinded_pubkey(identity_pubkey, TIME_PERIOD)
    
    # Then derive subcredential
    subcred = build_subcredential(identity_pubkey, blinded_pubkey)
    
    print()
    print(f"Computed subcredential: {subcred.hex()}")
    print(f"Expected subcredential: {expected_subcred.hex()}")
    print()
    
    if subcred == expected_subcred:
        print("✅ SUBCREDENTIAL MATCHES!")
        return True
    else:
        print("❌ SUBCREDENTIAL MISMATCH!")
        return False


if __name__ == "__main__":
    print("=" * 60)
    print("Testing Blinded Key Derivation Against Tor Test Vectors")
    print("=" * 60)
    print()
    
    blinded_ok = test_blinded_pubkey()
    subcred_ok = test_subcredential()
    
    print()
    print("=" * 60)
    if blinded_ok and subcred_ok:
        print("ALL TESTS PASSED!")
    else:
        print("SOME TESTS FAILED!")
    print("=" * 60)
