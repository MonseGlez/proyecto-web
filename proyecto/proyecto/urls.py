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
from perfil import views as uploader_views
from django.contrib import admin
from django.urls import path
from perfil.views import SignUpView, BienvenidaView,SignInView,SignOutView,FirmaView
from django.contrib.auth.views import LoginView, LogoutView 

#urlpatterns = [
#    path('admin/', admin.site.urls),
#]

urlpatterns = [
    url(r'^admin/', admin.site.urls),
    url(r'^$', BienvenidaView.as_view(), name='bienvenida'),
    url(r'^registrate/$', SignUpView.as_view(), name='sign_up'),

    url(r'^inicia-sesion/$', SignInView.as_view(), name='sign_in'),
    url(r'^cerrar-sesion/$', SignOutView.as_view(), name='sign_out'),
    url(r'^upload/$', uploader_views.UploadView.as_view(), name='fileupload'),
    #url(r'^upload', FirmaView.as_view(), name='fileupload'),

]
