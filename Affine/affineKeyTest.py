# This program proves that the keyspace of the affine cipher is limited
# to less than len(SYMBOLS) ^ 2.

import cryptomath
from affineCipherFunction import SYMBOLS, encryptMessage

message = 'Make things as simple as possible, but not simpler.'
for keyA in range(2, 80):
    key = keyA * len(SYMBOLS) + 1

    if cryptomath.gcd(keyA, len(SYMBOLS)) == 1:
        print(keyA, encryptMessage(key, message))
