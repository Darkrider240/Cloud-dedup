"""
Verifies our SPECK-128/128 against the official test vector from the
SIMON and SPECK paper (Beaulieu et al., NSA, 2013), Appendix C.

  Key:        0f0e0d0c0b0a0908 0706050403020100
  Plaintext:  6c61766975716520 7469206564616d20
  Ciphertext: a65d985179783265 7860fedf5c570d18
"""
from speck_cipher import _key_schedule, _encrypt_block, _decrypt_block

key = 0x0f0e0d0c0b0a09080706050403020100
pt = (0x6c61766975716520, 0x7469206564616d20)
expected_ct = (0xa65d985179783265, 0x7860fedf5c570d18)

rk = _key_schedule(key)
ct = _encrypt_block(pt[0], pt[1], rk)
print("Computed  :", hex(ct[0]), hex(ct[1]))
print("Expected  :", hex(expected_ct[0]), hex(expected_ct[1]))
assert ct == expected_ct, "SPECK does NOT match the official test vector"
assert _decrypt_block(ct[0], ct[1], rk) == pt, "Decrypt failed"
print("PASS: matches official Speck128/128 test vector (encrypt + decrypt)")
