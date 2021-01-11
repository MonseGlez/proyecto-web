from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.backends import default_backend
import sys
import hashlib
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import os


def generar_llave_privada():
    private_key = ec.generate_private_key(ec.SECP384R1(), default_backend())
    return private_key


def generar_llave_publica(llave_privada):
    return llave_privada.public_key()


def convertir_llave_privada_bytes(llave_privada):
    """
    Convierte de bytes a PEM
    """
    resultado = llave_privada.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )
    return resultado


def convertir_bytes_llave_privada(contenido_binario):
    """
    Convierte de PEM a bytes
    """
    resultado = serialization.load_pem_private_key(
        contenido_binario,
        backend=default_backend(),
        password=None)
    return resultado


def convertir_llave_publica_bytes(llave_publica):
    resultado = llave_publica.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return resultado


def convertir_bytes_llave_publica(contenido_binario):
    resultado = serialization.load_pem_public_key(
        contenido_binario,
        backend=default_backend())
    return resultado


def generar_llave_aes_from_password(password):
    password = password.encode('utf-8')
    derived_key = HKDF(algorithm=hashes.SHA256(),
                       length=32,
                       salt=None,
                       info=b'handshake data ',
                       backend=default_backend()).derive(password)
    return derived_key


def cifrar(mensaje, llave_aes, iv):
    aesCipher = Cipher(algorithms.AES(llave_aes), modes.CTR(iv),
                       backend=default_backend())
    cifrador = aesCipher.encryptor()
    cifrado = cifrador.update(mensaje)
    cifrador.finalize()
    return cifrado


def descifrar(cifrado, llave_aes, iv):
    aesCipher = Cipher(algorithms.AES(llave_aes), modes.CTR(iv),
                       backend=default_backend())
    descifrador = aesCipher.decryptor()
    plano = descifrador.update(cifrado)
    descifrador.finalize()
    return plano


def regresar_b_arch(path_archivo):
    contenido = ''
    with open(path_archivo, 'rb') as archivo:
        contenido = archivo.read()
    return contenido
def firmar(llave_privada,datos_firmar):
    datos = b'datos_firmar'
    firma = llave_privada.sign(datos, ec.ECDSA(hashes.SHA256()))
    return firma

