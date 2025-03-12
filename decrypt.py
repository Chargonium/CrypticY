from helpers.aes import decrypt_AES
from helpers.krypton import decrypt_krypton

with open("protected.data", "rb") as f:
    total_len = 16 + 16 + 160
    f.seek(-total_len, 2)
    tag = f.read(16) # Read the tag
    nonce = f.read(16) # Read the nonce
    verif_data = f.read(160) # Read the verification data
    size = f.tell()
    f.seek(0)
    data = f.read(size-total_len)

with open("protected.key", "rb") as f:
    salt_key = f.read(16) # Read the salt
    f.seek(-32, 2)
    tag_key = f.read(16) # Read the tag
    nonce_key = f.read(16) # Read the nonce
    size = f.tell()
    f.seek(16)
    encrypted_key = f.read(size-(32+16))

from Crypto.Protocol.KDF import PBKDF2
from Crypto.Cipher import AES

derived_key = PBKDF2(input("Password: "), salt_key, dkLen=32)
cipher = AES.new(derived_key, AES.MODE_GCM, nonce=nonce_key)
key = cipher.decrypt_and_verify(encrypted_key, tag_key)
key_aes = key[:32]
key_krypton = key[32:]

decrypted = decrypt_krypton(data, verif_data, key_krypton)
decrypted = decrypt_AES(decrypted, tag, nonce, key_aes)

print(decrypted.decode())
