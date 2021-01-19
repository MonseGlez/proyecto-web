"""proyecto URL Configuration

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/2.2/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from django.conf.urls import url
from perfil import views as uploader_views, views
from django.contrib import admin
from django.urls import path
from perfil.views import SignUpView, BienvenidaView,SignInView,SignOutView,VerifySign, updateKey
from django.contrib.auth.views import LoginView, LogoutView
from django.contrib.auth.decorators import login_required

#urlpatterns = [
#    path('admin/', admin.site.urls),
#]

urlpatterns = [
    url(r'^admin/', admin.site.urls),
    url(r'^$', login_required(BienvenidaView.as_view()), name='bienvenida'),
    url(r'^registrate/$', SignUpView.as_view(), name='sign_up'),
    url(r'^inicia-sesion/$', SignInView.as_view(), name='sign_in'),
    url(r'^cerrar-sesion/$', SignOutView.as_view(), name='sign_out'),
    url(r'^upload/$', login_required(uploader_views.UploadView.as_view()), name='fileupload'),
    url(r'^verificar-firma',login_required(VerifySign.as_view()),name='verify'),
    url(r'^nueva_llave', login_required(updateKey.as_view()),name='nueva_llave' ),

]
