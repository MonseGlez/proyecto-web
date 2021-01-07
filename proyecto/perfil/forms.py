from django import forms
from django.contrib.auth.forms import UserCreationForm, AuthenticationForm
from django.contrib.auth.models import User
from .models import Upload

class SignUpForm(UserCreationForm):
    Nombre = forms.CharField(max_length=140, required=True)
    Apellido = forms.CharField(max_length=140, required=False)
    email = forms.EmailField(required=True)

    class Meta:
        model = User
        fields = (
            'username',
            'email',
            'Nombre',
            'Apellido',
            'password1',
            'password2',
        )


class UploadForm(forms.ModelForm):
    password = forms.CharField(widget=forms.PasswordInput)
    class Meta:
        model = Upload
        fields = ['upload_file',
                  'password']
        widgets = {
            'password': forms.PasswordInput()
        }
