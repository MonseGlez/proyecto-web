# Generated by Django 3.1.5 on 2021-01-07 22:25

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('perfil', '0003_upload_contraseña'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='upload',
            name='contraseña',
        ),
    ]
