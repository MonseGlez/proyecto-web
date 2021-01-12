from django import forms
from django.contrib.auth.forms import UserCreationForm, AuthenticationForm
from django.contrib.auth.models import User
from .models import Upload

class SignUpForm(UserCreationForm):
    first_name = forms.CharField(max_length=140, required=True, label="Nombre")
    last_name= forms.CharField(max_length=140, required=False, label="Apellido")
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
    password = forms.CharField(widget=forms.PasswordInput)
    upload_file = forms.FileField(label='Archivo')
    class Meta:
        model = Upload
        fields = ['upload_file',
                  'password']
        widgets = {
            'password': forms.PasswordInput()
        }
