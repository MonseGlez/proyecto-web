from django.http import HttpResponse, request
from .utils import *
from os import remove
# Create your views here.
from django.contrib.auth import get_user_model
from django.contrib.auth.models import User
from django.shortcuts import render, redirect
from django.contrib.auth import login, authenticate
from django.utils.encoding import smart_str
from django.views.generic import TemplateView
from .models import Perfil
from .forms import SignUpForm, UploadForm, VerifySignForm
from django.contrib.auth.views import LoginView, LogoutView
from django.views.generic.edit import CreateView
from django.urls import reverse_lazy
from .models import Upload, VerifySign
from django.views.decorators.csrf import csrf_protect
from django.contrib.auth.decorators import login_required
from django.contrib.auth.hashers import make_password, check_password




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
        login(self.request, usuario)

        usuario2 = form.cleaned_data.get('username')
        path_privada = './llaves/' +usuario2 + 'privada.pem.cif'
        path_publica = './llaves/' +usuario2 + 'publica.pem'
        iv = b"M\xb0%\xafd)\xe7\x11@7'\xb0\xcc\xc9\x81\xe2"
        llave_aes = generar_llave_aes_from_password(password)
        llave_privada = generar_llave_privada()
        llave_publica = generar_llave_publica(llave_privada)
        with open(path_privada, 'wb') as salida_privada:
            contenido = cifrar(convertir_llave_privada_bytes(llave_privada), llave_aes, iv)
            salida_privada.write(contenido)
        salida_privada.close()
        with open(path_publica, 'wb') as salida_publica:
            contenido = convertir_llave_publica_bytes(llave_publica)
            salida_publica.write(contenido)
        salida_publica.close()


class BienvenidaView(TemplateView):
    template_name = 'perfil/bienvenida.html'


class SignInView(LoginView):
    template_name = 'perfil/iniciar_sesion.html'


class SignOutView(LogoutView):
    pass


class VerifySingView(TemplateView):
    template_name = 'perfil/verifysign_form.html'


class UploadView(CreateView):
    model = Upload
    form_class = UploadForm

    #success_url = reverse_lazy('fileupload')

    def form_valid(self, form):
        form.save()
        nombre = self.request.user.username
        archivo = form.cleaned_data.get('upload_file').read()
        password = form.cleaned_data.get('password')
        llave_aes = generar_llave_aes_from_password(password)
        iv = b"M\xb0%\xafd)\xe7\x11@7'\xb0\xcc\xc9\x81\xe2"
        path_privada_des ='./llaves/' + nombre + 'privada.pem'
        path_privada_cif = './llaves/' +nombre + 'privada.pem.cif'

        with open(path_privada_des, 'wb') as salida_des:
            contenido = descifrar(regresar_b_arch(path_privada_cif), llave_aes, iv)
            salida_des.write(contenido)
        salida_des.close()
        llave_priv = convertir_bytes_llave_privada(contenido)
        firma = firmar(llave_priv, archivo)
        nombre_firma = 'firma' + nombre
        print (firma)
        remove(path_privada_des)
        with open(nombre_firma, 'wb') as firmado:
            contenido = firma
            firmado.write(contenido)
        print(contenido)

        response = HttpResponse(open(nombre_firma, 'rb').read())
        response['Content-Type'] = 'text/plain'
        response['Content-Disposition'] = "attachment; filename=" + nombre_firma
        return response


class VerifySign(CreateView):
    model = VerifySign
    form_class = VerifySignForm









