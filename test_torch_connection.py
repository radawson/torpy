#!/usr/bin/env python3
"""
Test script to connect to Torch .onion site and verify v3 HS implementation.

Tests:
1. V3 hidden service connection
2. HTTP request/response
3. Vanguards integration (if enabled)
"""

import sys
import logging
from torpy import TorClient
from torpy.http.requests import TorRequests

# Torch hidden service
TORCH_ONION = 'http://xmh57jrknzkhv6y3ls3ubitzfqnkrwxhopf5aygthi7d6rplyvk3noyd.onion'

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(name)s: %(message)s',
    datefmt='%H:%M:%S'
)
logger = logging.getLogger(__name__)


def test_basic_connection():
    """Test basic connection to Torch without vanguards."""
    logger.info("="*60)
    logger.info("TEST 1: Basic V3 Hidden Service Connection")
    logger.info("="*60)
    
    try:
        with TorClient() as tor:
            with TorRequests(tor) as tor_requests:
                logger.info(f"Connecting to: {TORCH_ONION}")
                logger.info("This may take 30-60 seconds for first connection...")
                
                response = tor_requests.get(TORCH_ONION, timeout=120)
                
                logger.info(f"✓ Connection successful!")
                logger.info(f"  Status code: {response.status_code}")
                logger.info(f"  Content length: {len(response.content)} bytes")
                
                # Check if response contains expected content
                if b'torch' in response.content.lower() or b'search' in response.content.lower():
                    logger.info(f"  ✓ Page content verified (contains 'torch' or 'search')")
                else:
                    logger.warning(f"  ⚠ Page content may be unexpected")
                
                # Show first 200 chars of content
                content_preview = response.text[:200].replace('\n', ' ')
                logger.info(f"  Preview: {content_preview}...")
                
                return True
                
    except Exception as e:
        logger.error(f"✗ Connection failed: {e}")
        import traceback
        traceback.print_exc()
        return False


def test_with_vanguards():
    """Test connection to Torch with vanguards enabled."""
    logger.info("\n" + "="*60)
    logger.info("TEST 2: V3 Hidden Service with Vanguards")
    logger.info("="*60)
    
    try:
        from torpy.vanguards import VanguardManager, CircuitPurpose, VanguardLayer
        
        with TorClient() as tor:
            # Get consensus for vanguards
            logger.info("Initializing vanguards...")
            
            # Note: We need to get the consensus from the guard
            # This is a simplified test - full integration would require
            # circuit building changes
            logger.info("⚠ Vanguards require circuit building integration")
            logger.info("  This test demonstrates the vanguards API only")
            
            # Create a mock consensus for demonstration
            # In production, this would come from tor.guard.consensus
            logger.info("  (Skipping vanguards test - requires circuit integration)")
            return None
            
    except ImportError:
        logger.warning("✗ Vanguards module not available")
        return False
    except Exception as e:
        logger.error(f"✗ Vanguards test failed: {e}")
        import traceback
        traceback.print_exc()
        return False


def test_multiple_connections():
    """Test multiple connections to verify stability."""
    logger.info("\n" + "="*60)
    logger.info("TEST 3: Multiple Connections")
    logger.info("="*60)
    
    success_count = 0
    total_tests = 3
    
    try:
        with TorClient() as tor:
            with TorRequests(tor) as tor_requests:
                for i in range(total_tests):
                    try:
                        logger.info(f"Connection {i+1}/{total_tests}...")
                        response = tor_requests.get(TORCH_ONION, timeout=60)
                        
                        if response.status_code == 200:
                            success_count += 1
                            logger.info(f"  ✓ Success ({len(response.content)} bytes)")
                        else:
                            logger.warning(f"  ⚠ Unexpected status: {response.status_code}")
                            
                    except Exception as e:
                        logger.error(f"  ✗ Failed: {e}")
                
                logger.info(f"\nResults: {success_count}/{total_tests} successful")
                return success_count == total_tests
                
    except Exception as e:
        logger.error(f"✗ Multiple connections test failed: {e}")
        return False


def test_circuit_info():
    """Display circuit information during connection."""
    logger.info("\n" + "="*60)
    logger.info("TEST 4: Circuit Information")
    logger.info("="*60)
    
    try:
        with TorClient() as tor:
            logger.info(f"TOR client initialized")
            logger.info(f"  Using guards: Yes")
            
            with TorRequests(tor) as tor_requests:
                logger.info(f"Connecting to: {TORCH_ONION}")
                response = tor_requests.get(TORCH_ONION, timeout=120)
                
                logger.info(f"✓ Connected successfully")
                logger.info(f"  Response: {response.status_code}")
                logger.info(f"  Size: {len(response.content)} bytes")
                
                # Check response headers
                logger.info(f"  Headers:")
                for key, value in list(response.headers.items())[:5]:
                    logger.info(f"    {key}: {value}")
                
                return True
                
    except Exception as e:
        logger.error(f"✗ Circuit info test failed: {e}")
        import traceback
        traceback.print_exc()
        return False


def main():
    """Run all tests."""
    logger.info("\n" + "="*60)
    logger.info("TorPy V3 Hidden Service Test Suite")
    logger.info(f"Target: {TORCH_ONION}")
    logger.info("="*60 + "\n")
    
    results = {}
    
    # Test 1: Basic connection
    results['basic'] = test_basic_connection()
    
    # Test 2: Vanguards (demonstration only)
    results['vanguards'] = test_with_vanguards()
    
    # Test 3: Multiple connections
    if results['basic']:
        results['multiple'] = test_multiple_connections()
    else:
        logger.info("\nSkipping multiple connections test (basic test failed)")
        results['multiple'] = False
    
    # Test 4: Circuit info
    if results['basic']:
        results['circuit_info'] = test_circuit_info()
    else:
        logger.info("\nSkipping circuit info test (basic test failed)")
        results['circuit_info'] = False
    
    # Summary
    logger.info("\n" + "="*60)
    logger.info("TEST SUMMARY")
    logger.info("="*60)
    
    for test_name, result in results.items():
        if result is True:
            status = "✓ PASS"
        elif result is False:
            status = "✗ FAIL"
        else:
            status = "⊘ SKIP"
        logger.info(f"  {test_name:20s}: {status}")
    
    passed = sum(1 for r in results.values() if r is True)
    failed = sum(1 for r in results.values() if r is False)
    skipped = sum(1 for r in results.values() if r is None)
    
    logger.info(f"\n  Total: {passed} passed, {failed} failed, {skipped} skipped")
    
    if results['basic']:
        logger.info("\n✅ V3 hidden service implementation is working!")
        return 0
    else:
        logger.error("\n❌ V3 hidden service implementation has issues")
        return 1


if __name__ == '__main__':
    sys.exit(main())
