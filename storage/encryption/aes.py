from cryptography.fernet import Fernet

def generate_aes_key():
    return Fernet.generate_key()

def encrypt_bytes(data: bytes, aes_key: bytes) -> bytes:
    f = Fernet(aes_key)
    return f.encrypt(data)

def decrypt_bytes(token: bytes, aes_key: bytes) -> bytes:
    f = Fernet(aes_key)
    return f.decrypt(token)
