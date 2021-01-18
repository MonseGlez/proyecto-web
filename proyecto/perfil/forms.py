from django import forms
from django.contrib.auth.forms import UserCreationForm, AuthenticationForm
from django.contrib.auth.models import User
from .models import Upload, VerifySign


class SignUpForm(UserCreationForm):
    first_name = forms.CharField(max_length=140, required=True, label="Nombre")
    last_name = forms.CharField(max_length=140, required=True, label="Apellido")
    email = forms.EmailField(required=True)

    class Meta:
        model = User
        fields = (
            'username',
            'email',
            'first_name',
            'last_name',
            'password1',
            'password2',
        )


class UploadForm(forms.ModelForm):
    password = forms.CharField(widget=forms.PasswordInput, required=True)
    upload_file = forms.FileField(label='Sube el archivo para crear la firma.', required=True)

    class Meta:
        model = Upload
        fields = ['upload_file',
                  'password']
        widgets = {
            'password': forms.PasswordInput()
        }


class VerifySignForm(forms.ModelForm):
    upload_file = forms.FileField(label='Sube archivo verificar firma', required=True)
    upload_firma = forms.FileField(label='Sube archivo que contiene la firma', required=True)
    usuario = forms.CharField(label='Ingresa el nombre del usuario de la firma')
    class Meta:
        model = Upload
        fields = ['upload_file',
                  'upload_firma' ,'usuario']
