#! /usr/bin/env nix-shell
#! nix-shell -i python3 -p python3Packages.pyotp

from base64 import b32encode
import pyotp

totp = pyotp.TOTP(b32encode(b"12345678901234567890"), 8)
print(totp.now())
