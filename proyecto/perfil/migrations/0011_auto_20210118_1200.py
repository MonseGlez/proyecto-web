# Generated by Django 2.2.7 on 2021-01-18 12:00

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('perfil', '0010_auto_20210116_0257'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='perfil',
            name='llave_privada',
        ),
        migrations.RemoveField(
            model_name='perfil',
            name='llave_publica',
        ),
    ]
