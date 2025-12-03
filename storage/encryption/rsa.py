from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP

def generate_rsa_keypair(bits: int = 2048):
    key = RSA.generate(bits)
    private_pem = key.export_key()        # bytes (PEM)
    public_pem = key.publickey().export_key()
    return public_pem, private_pem

def rsa_encrypt(public_pem: bytes, data: bytes) -> bytes:
    rsa_key = RSA.import_key(public_pem)
    cipher = PKCS1_OAEP.new(rsa_key)
    return cipher.encrypt(data)

def rsa_decrypt(private_pem: bytes, ciphertext: bytes) -> bytes:
    rsa_key = RSA.import_key(private_pem)
    cipher = PKCS1_OAEP.new(rsa_key)
    return cipher.decrypt(ciphertext)
