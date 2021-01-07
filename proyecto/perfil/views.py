from typing import Optional, Any

from django.shortcuts import render
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
import sys

import hashlib
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import os
# Create your views here.
from django.shortcuts import render, redirect
from django.contrib.auth import login, authenticate

from django.views.generic import CreateView, TemplateView

from .models import Perfil

from .forms import SignUpForm, UploadForm
from django.contrib.auth.views import LoginView
from django.contrib.auth.views import LoginView, LogoutView 

from django.views.generic.edit import CreateView
from django.urls import reverse_lazy
from .models import Upload
from django.contrib.auth.decorators import login_required


class SignUpView(CreateView):
    model = Perfil
    form_class = SignUpForm

    def form_valid(self, form):
        '''
        En este parte, si el formulario es valido guardamos lo que se obtiene de él y usamos authenticate para que el usuario incie sesión luego de haberse registrado y lo redirigimos al index
        '''
        form.save()

        usuario = form.cleaned_data.get('username')
        password = form.cleaned_data.get('password1')
        usuario = authenticate(username=usuario, password=password)
        usuario2 = form.cleaned_data.get('username')
        path_privada = usuario2 + 'privada.pem'
        path_publica = usuario2 + 'publica.pem'
        iv = os.urandom(16)
        llave_aes = generar_llave_aes_from_password(password)
        llave_privada = generar_llave_privada()
        llave_publica = generar_llave_publica(llave_privada)
        with open(path_privada, 'wb') as salida_privada:
            contenido = cifrar(convertir_llave_privada_bytes(llave_privada),llave_aes,iv)
            contenido2 = descifrar(contenido,llave_aes,iv)
            salida_privada.write(contenido)

        with open(path_publica, 'wb') as salida_publica:
            contenido = convertir_llave_publica_bytes(llave_publica)
            salida_publica.write(contenido)
        login(self.request,usuario)
        return redirect('/')



class BienvenidaView(TemplateView):
   template_name = 'perfil/bienvenida.html'

class SignInView(LoginView):
   template_name = 'perfil/iniciar_sesion.html'

class SignOutView(LogoutView):
   pass
@login_required()
class FirmaView(TemplateView):
    template_name = 'perfil/upload_form.html'

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

class UploadView(CreateView):
    model = Upload
    form_class = UploadForm
    success_url = reverse_lazy('fileupload')



