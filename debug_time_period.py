#!/usr/bin/env python3
"""Debug script to check time period and blinded key calculations."""

from torpy.hs_ntor import get_time_period_num, TIME_PERIOD_LENGTH, TIME_PERIOD_ROTATION_OFFSET, derive_blinded_pubkey
from torpy.hiddenservice import HiddenService
from torpy.crypto_common import sha3_256
import time
from base64 import b64encode, b64decode

# DuckDuckGo onion address
DDG_ONION = "duckduckgogg42xjoc72x3sjasowoarfbgcmvfimaftt6twagswzczad.onion"

now = int(time.time())
tp = get_time_period_num(now)

print(f"Current Unix Time: {now}")
print(f"Time Period Length (seconds): {TIME_PERIOD_LENGTH}")
print(f"Rotation Offset (seconds): {TIME_PERIOD_ROTATION_OFFSET}")
print(f"Time Period Number: {tp}")
print(f"Minutes in day: {(now % 86400) // 60}")

# Calculate when the current period started
period_start = tp * TIME_PERIOD_LENGTH + TIME_PERIOD_ROTATION_OFFSET
print(f"Current Period Started: {period_start} (TP {tp})")
print(f"Seconds into period: {now - period_start}")

# Check hour for SRV selection  
hour = (now % 86400) // 3600
srv_choice = "PREVIOUS" if hour < 12 else "CURRENT"
print(f"Hour (UTC): {hour}")
print(f"SRV Selection: {srv_choice}")

# Create hidden service and get blinded key
print("\n--- DuckDuckGo Blinded Key ---")
hs = HiddenService(DDG_ONION)
print(f"Is V3: {hs.is_v3}")
print(f"Identity pubkey (hex): {hs._identity_pubkey.hex()}")

blinded = hs.get_blinded_pubkey(tp)
print(f"Blinded pubkey (hex): {blinded.hex()}")

# Convert to URL format
url_key = b64encode(blinded).decode().replace('=', '').replace('+', '-').replace('/', '_')
print(f"URL key (base64url): {url_key}")
print(f"Expected URL: /tor/hs/3/{url_key}")
