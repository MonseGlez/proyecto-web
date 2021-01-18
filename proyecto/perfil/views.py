from collections import UserList

from django.http import HttpResponse, request
from requests import Response
from django.contrib.auth.hashers import check_password
from .utils import *
from os import remove
# Create your views here.
from django.forms.models import model_to_dict
from django.contrib import messages
from django.shortcuts import redirect, render, render_to_response
from django.contrib.auth import login, authenticate
from django.views.generic import TemplateView, DetailView
from .models import Perfil
from .forms import SignUpForm, UploadForm, VerifySignForm
from django.contrib.auth.views import LoginView, LogoutView
from django.views.generic.edit import CreateView
from .models import Upload, VerifySign
from django.contrib.auth.models import User
from django.views.generic import ListView
from threading import Timer

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
        #se crea un hilo para realize la funcion de invalidar las llaves despues de x tiempo
        h = Timer(600.0, deadkey, (usuario2,))
        h.start()

        return redirect('/')


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
    def form_valid(self, form):
        form.save()
        nombre = self.request.user.username
        currentpassword = self.request.user.password
        archivo = form.cleaned_data.get('upload_file').read()
        archivo_nombre = form.cleaned_data.get('upload_file').name
        password = form.cleaned_data.get('password')
        matchcheck= check_password(password, currentpassword)
        if matchcheck is not False:
            llave_aes = generar_llave_aes_from_password(password)
            iv = b"M\xb0%\xafd)\xe7\x11@7'\xb0\xcc\xc9\x81\xe2"
            path_privada_des ='./llaves/' + nombre + 'privada.pem'
            path_privada_cif = './llaves/' +nombre + 'privada.pem.cif'
            with open(path_privada_des, 'wb') as salida_des:
                contenido = descifrar(regresar_b_arch(path_privada_cif), llave_aes, iv)
                salida_des.write(contenido)
            llave_priv = convertir_bytes_llave_privada(contenido)
            firma = firmar(llave_priv, archivo)
            nombre_firma = './firmas/firma' + nombre + archivo_nombre
            remove(path_privada_des)
            with open(nombre_firma, 'wb') as firmado:
                contenido = firma
                firmado.write(contenido)
            response = HttpResponse(open(nombre_firma, 'rb').read())
            response['Content-Type'] = 'text/plain'
            response['Content-Disposition'] = "attachment; filename=firma"+nombre +archivo_nombre
            remove(nombre_firma)
            return response
        else:
            messages.error(self.request,'La contraseña que ingresaste no coincide, intenta de nuevo')
            return redirect('/upload')

class VerifySign(CreateView):
    model = VerifySign
    form_class = VerifySignForm
    def form_valid(self, form):
        users = [str(user) for user in User.objects.all()]
        form.save()

        usuario = form.cleaned_data.get('usuario')
        if usuario in users:
            path_publica = './llaves/' + usuario + 'publica.pem'
            llave_publica = convertir_bytes_llave_publica(regresar_b_arch(path_publica))
            archivo = form.cleaned_data.get('upload_file').read()
            firma = form.cleaned_data.get('upload_firma').read()
            try:
                llave_publica.verify(firma,archivo,ec.ECDSA(hashes.SHA256()))
                print('La firma es válida')
                messages.success(self.request, 'La firma es válida.')
                return redirect('/verificar-firma')
            except InvalidSignature:
                print("La firma es inválida")
                messages.error(self.request, 'La firma es inválida.')
                return redirect('/verificar-firma')
        else:

            messages.error(self.request, 'el usuario no existe, no tiene firmas')
            return redirect('/verificar-firma')



























