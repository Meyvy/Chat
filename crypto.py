import os
import cryptography.hazmat.primitives.hashes as hashes
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import padding as asym_padding
from cryptography.hazmat.primitives import serialization
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import x25519
from numpy import byte

from project.server.database import PASSWORD


SYM_KEY_SIZE = 32
IV_SIZE = 16
BLOCK_SIZE = 128
PUBLIC_EXPONENT = 65537
ASYM_KEY_SIZE = 4096
ENCRYPT_PASS = b'6174'


def hash(message: str) -> byte:
    digest = hashes.Hash(hashes.SHA512())
    digest.update(message.encode('UTF-8'))
    return digest.finalize()


def sym_key() -> tuple:
    return os.urandom(SYM_KEY_SIZE), os.urandom(IV_SIZE)


def rsa_key() -> tuple:
    sk = rsa.generate_private_key(
        public_exponent=PUBLIC_EXPONENT, key_size=ASYM_KEY_SIZE)
    pk = sk.public_key()
    return sk, pk


def ec_key() -> tuple:
    pass


def seriliaze_rsa_private_key(sk):
    ssk = sk.private_bytes(encoding=serialization.Encoding.PEM,
                           format=serialization.PrivateFormat.PKCS8,
                           encryption_algorithm=serialization.BestAvailableEncryption(ENCRYPT_PASS))
    return ssk


def seriliaze_rsa_public_key(pk):
    spk = pk.public_bytes(encoding=serialization.Encoding.PEM,
                          format=serialization.PublicFormat.SubjectPublicKeyInfo)
    return spk


def read_rsa_private_key(path):
    with open(path, "rb") as key_file:
        sk = serialization.load_pem_private_key(
            key_file.read(),
            password=ENCRYPT_PASS
        )
    return sk


def read_rsa_public_key(path):
    with open(path, "rb") as key_file:
        pk = serialization.load_pem_public_key(
            key_file.read()
        )
    return pk


def write(path, b_content):
    with open(path, "wb") as f:
        f.write(b_content)
        f.close()


def sym_enc(message, private_key):
    message = message.encode('UTF-8') if type(message) == str else message
    padder = padding.PKCS7(BLOCK_SIZE).padder()
    message = padder.update(message)+padder.finalize()
    cipher = Cipher(algorithms.AES(private_key[0]), modes.CBC(private_key[1]))
    encryptor = cipher.encryptor()
    cipher_text = encryptor.update(message)+encryptor.finalize()
    return cipher_text


def sym_dec(cipher_text, private_key):
    cipher_text = cipher_text.encode('UTF-8') if type(cipher_text) == str else cipher_text
    cipher = Cipher(algorithms.AES(private_key[0]), modes.CBC(private_key[1]))
    decryptor = cipher.decryptor()
    message = decryptor.update(cipher_text)+decryptor.finalize()
    unpadder = padding.PKCS7(BLOCK_SIZE).unpadder()
    message = unpadder.update(message)+unpadder.finalize()
    return message.decode()


def rsa_enc(message, pk):
    message = message.encode('UTF-8') if type(message) == str else message
    return pk.encrypt(message, asym_padding.OAEP(
        mgf=asym_padding.MGF1(algorithm=hashes.SHA512()),
        algorithm=hashes.SHA512(),
        label=None
    ))


def rsa_dec(cipher_text, sk):
    return sk.decrypt(cipher_text, asym_padding.OAEP(
        mgf=asym_padding.MGF1(algorithm=hashes.SHA512()),
        algorithm=hashes.SHA512(),
        label=None
    )).decode()


def rsa_sign(message, sk):
    message = message.encode('UTF-8') if type(message) == str else message
    return sk.sign(
        message,
        asym_padding.PSS(
            mgf=asym_padding.MGF1(algorithm=hashes.SHA512()),
            salt_length=asym_padding.PSS.MAX_LENGTH
        ),
        hashes.SHA512()
    )


def rsa_verify(signature, message, pk):
    message = message.encode('UTF-8') if type(message) == str else message
    try:
        pk.verify(
            signature,
            message,
            asym_padding.PSS(
                mgf=asym_padding.MGF1(algorithm=hashes.SHA512()),
                salt_length=asym_padding.PSS.MAX_LENGTH),
            hashes.SHA512()
        )
        return True
    except InvalidSignature as err:
        return False


