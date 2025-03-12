import os
from quantcrypt.cipher import Krypton

def encrypt_krypton(data: bytes) -> tuple[bytes, bytes, bytes]:
    """
    Encrypts the data using the Krypton encryption algorithm.\n
    Returns a tuple with the encrypted data, the verification data and the key.
    """
    key = os.urandom(64)
    kyberCrystal = Krypton(key)
    kyberCrystal.begin_encryption()
    enc = kyberCrystal.encrypt(data)
    verif_data = kyberCrystal.finish_encryption()
    return enc, verif_data, key

def decrypt_krypton(data: bytes, verif_data: bytes, key: bytes) -> bytes:
    """
    Decrypts the data using the Krypton encryption algorithm.\n
    Returns the decrypted data.
    """
    kyberCrystal = Krypton(key)
    kyberCrystal.begin_decryption(verif_data)
    return kyberCrystal.decrypt(data)

if __name__ == "__main__":
    # Testing function

    data = b"Hello, World"
    encrypted, verif_data, key = encrypt_krypton(data)
    print(f"Encrypted:   {encrypted.hex()}")
    print(f"Verif. Data: {verif_data.hex()}")
    print(f"Key:         {key.hex()}")
    decrypted = decrypt_krypton(encrypted, verif_data, key)
    print(f"Decrypted:   {decrypted.decode()}")
