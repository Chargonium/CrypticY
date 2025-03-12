from helpers.aes import encrypt_AES
from helpers.krypton import encrypt_krypton

import os
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Random import get_random_bytes

with open("unprotected.data", "rb") as f:
    data = f.read()

# First, Encrypt using AES

encrypted, tag, nonce, key_aes = encrypt_AES(data)

# Then, Encrypt using Krypton

encrypted, verif_data, key_krypton = encrypt_krypton(encrypted)

# Finally, save the data

with open("protected.data", "wb") as f:
    f.write(encrypted)
    f.write(tag)
    f.write(nonce)
    f.write(verif_data)

# And save the key (obviously)

key = key_aes + key_krypton

salt = get_random_bytes(16)
derived_key = PBKDF2(input("Password: "), salt, dkLen=32)

cipher = AES.new(derived_key, AES.MODE_GCM)

encrypted_key, tag = cipher.encrypt_and_digest(key)

with open("protected.key", "wb") as f:
    f.write(salt)
    f.write(encrypted_key)
    f.write(tag)
    f.write(cipher.nonce)