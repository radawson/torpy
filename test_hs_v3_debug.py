#!/usr/bin/env python3
"""Quick debug test for v3 hidden service INTRODUCE/RENDEZVOUS."""

import logging
import sys

# Setup logging for maximum visibility
logging.basicConfig(
    level=logging.DEBUG,
    format='[%(asctime)s] [%(name)-18s] %(message)s',
    datefmt='%H:%M:%S'
)

# Reduce noise from less relevant modules
for mod in ['urllib3', 'requests', 'OpenSSL']:
    logging.getLogger(mod).setLevel(logging.WARNING)

from torpy import TorClient

# DuckDuckGo v3 hidden service
ONION_ADDRESS = 'duckduckgogg42xjoc72x3sjasowoarfbgcmvfimaftt6twagswzczad.onion'

def main():
    print("="*70)
    print("V3 Hidden Service INTRODUCE/RENDEZVOUS Debug Test")
    print("="*70)
    
    try:
        with TorClient() as tor:
            print(f"\n[*] Creating hidden service connector for: {ONION_ADDRESS}")
            
            # Get a guard for our circuit
            with tor.create_circuit(3) as circuit:
                print(f"[*] Created 3-hop circuit: {circuit}")
                
                # Try to create the HS stream
                print("[*] Attempting to connect (INTRODUCE1 -> RENDEZVOUS2)...")
                print("    Watch for 'V3 Introduced' and 'CellRelayRendezvous2' in logs")
                print("-"*70)
                
                with circuit.create_stream((ONION_ADDRESS, 80)) as stream:
                    print("[+] SUCCESS! Stream created to hidden service")
                    # Send minimal HTTP request
                    stream.send(b'GET / HTTP/1.0\r\nHost: ' + ONION_ADDRESS.encode() + b'\r\n\r\n')
                    response = stream.recv(512)
                    print(f"[+] Response (first 200 bytes):\n{response[:200]}")
                    
    except Exception as e:
        print(f"\n[ERROR] {type(e).__name__}: {e}")
        import traceback
        traceback.print_exc()
        return 1
    
    return 0

if __name__ == '__main__':
    sys.exit(main())
