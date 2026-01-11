"""Simple test for HSDir bulk download."""
import logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s %(name)s: %(message)s')

from torpy import TorClient
from torpy.hiddenservice import HiddenService

print("Testing HSDir bulk download for v3 hidden services...")

c = TorClient()
print("TorClient created")

with c.get_guard() as guard:
    print(f"Got guard: {guard}")
    
    hs = HiddenService('duckduckgogg42xjoc72x3sjasowoarfbgcmvfimaftt6twagswzczad.onion')
    print(f"HiddenService: {hs.onion_address}")
    
    print("\nGetting responsibles (this will download descriptors)...")
    responsibles = list(c.consensus.get_responsibles(hs))
    
    print(f"\nFound {len(responsibles)} responsible HSDirs:")
    for router, replica in responsibles:
        print(f"  Replica {replica}: {router.nickname} ({router.fingerprint.hex()[:16]}...)")
