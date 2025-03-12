import os
from Crypto.Cipher import AES

def encrypt_AES(data: bytes) -> tuple[bytes, bytes, bytes, bytes]:
    """
    Encrypts the data using the AES encryption algorithm.\n
    Returns a tuple with the encrypted data, the tag, the nonce and the key.
    """
    key = os.urandom(32)
    cipher = AES.new(key, AES.MODE_GCM)
    encrypted, tag = cipher.encrypt_and_digest(data)
    return encrypted, tag, cipher.nonce, key

def decrypt_AES(data: bytes, tag: bytes, nonce: bytes, key: bytes) -> bytes:
    """
    Decrypts the data using the AES encryption algorithm.\n
    Returns the decrypted data.
    """
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    return cipher.decrypt_and_verify(data, tag)

if __name__ == "__main__":
    # Testing function

    data = b"Hello, World, This is a really cool test!"
    encrypted, tag, nonce, key = encrypt_AES(data)
    print(f"Encrypted: {encrypted.hex()}")
    print(f"Tag:       {len(tag)}")
    print(f"Nonce:     {len(nonce)}")
    print(f"Key:       {len(key)}")
    decrypted = decrypt_AES(encrypted, tag, nonce, key)
    print(f"Decrypted: {decrypted.decode()}")