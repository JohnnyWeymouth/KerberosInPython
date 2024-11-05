from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend

# Public key string (PEM format)
def encrypt_with_public_key(message:bytes, public_key_str:str) -> bytes:
    # Load the public key
    public_key = serialization.load_pem_public_key(
        public_key_str.encode(),
        backend=default_backend()
    )
    # Encrypt the message
    ciphertext = public_key.encrypt(
        message,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return ciphertext

def decrypt_with_private_key(ciphertext:bytes, private_key_str:str) -> str:
    # Load the private key
    private_key = serialization.load_pem_private_key(
        private_key_str.encode(),
        password=None,  # If the private key has a passphrase, replace `None` with the password as bytes
        backend=default_backend()
    )
    # Decrypt the message
    plaintext = private_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return plaintext.decode()


public_key_str = """-----BEGIN PUBLIC KEY-----
MIGeMA0GCSqGSIb3DQEBAQUAA4GMADCBiAKBgF3mfC9t6fxtNlO8SRZMmcoE+khJ
FIiTbJTyBzysAjSHaYEIG5XQou1e619lDG+Zgw2UQkLyjCesMknSphuhAQMseOhy
dnKJ62fgESVLOb07Nso4Od3JByS/TL0wLqPNzrFKOxEIIBnFyhaDHfrt0j9cVsX1
z1VmaqnHwWgDRm8lAgMBAAE=
-----END PUBLIC KEY-----"""

message = b'lol please work'

ciphertext = encrypt_with_public_key(message, public_key_str)
print(ciphertext)

# Private key string (PEM format)
private_key_str = """-----BEGIN RSA PRIVATE KEY-----
MIICWgIBAAKBgF3mfC9t6fxtNlO8SRZMmcoE+khJFIiTbJTyBzysAjSHaYEIG5XQ
ou1e619lDG+Zgw2UQkLyjCesMknSphuhAQMseOhydnKJ62fgESVLOb07Nso4Od3J
ByS/TL0wLqPNzrFKOxEIIBnFyhaDHfrt0j9cVsX1z1VmaqnHwWgDRm8lAgMBAAEC
gYBbnRWKnN2Ot+sqVWilhgUB0ktynUKYYeWtiFnBOz1HjNpF1ug7Cfz8RQC16Pvy
Ij93zy+667QMvPeviQMhr7sw81nO27ipqR/OcTt/DRj30StXZkaHhaZXBDGQcJKU
+6qll2QeFHDIrQGoVap3OSyHb2uqkcgKK/sXJVZ6HtiPgQJBAKVC1PNaSRzR5lYB
S4arXF0GVYqJwWWeqEj7mZV6BPFFArS/9H2q+X1qsys3WTr6DpZ8aCygX7QNYZAr
bC+tEUUCQQCRdShQR99h/M4nXf9gR5bnuryqluBeRqX4ZgceFSOptFYVCSDnE1DC
nraL+UTuN1oQKT01xepEIC5nU9AXy5RhAkAajjGv5QsokWYE3fJn8nNGE3V9bINi
M+twxtU4GsJejqtPpiTAaM/sYk/mGt/AxVvAvL70pNScFyZdR0z8IEBNAkBC71TD
zK8g2kLLnte7qHXq4OWc4p0RBRWu/tRbpYKpv1C1kWPQsfTB+mMqemSb8mDBexit
vAuXme+AoPLrYEVBAkAuaOTzJ+6tDklR3i1xPxhd7Vd4AoFWOdk91gim4IgyMwJN
8ff1sk6XlHSgdJiAREPqwOgpeR5ZA9kh1OMS/eMW
-----END RSA PRIVATE KEY-----"""

message = decrypt_with_private_key(ciphertext, private_key_str)
print(message)