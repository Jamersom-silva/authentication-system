from django.contrib.auth.models import AbstractBaseUser, BaseUserManager, PermissionsMixin
from django.db import models

class MeuUserManager(BaseUserManager):
    def create_user(self, email, password=None, nome=None, username=None, **extra_fields):
        if not email:
            raise ValueError('Email obrigatório')
        email = self.normalize_email(email)
        user = self.model(email=email, nome=nome, username=username, **extra_fields)
        user.set_password(password)
        user.save()
        return user

    def create_superuser(self, email, password, nome=None, username=None, **extra_fields):
        user = self.create_user(email, password, nome=nome, username=username, **extra_fields)
        user.is_staff = True
        user.is_superuser = True
        user.is_active = True
        user.save()
        return user

class User(AbstractBaseUser, PermissionsMixin):
    email = models.EmailField(unique=True)
    username = models.CharField(max_length=50, unique=False, null=True, blank=True)
    nome = models.CharField(max_length=100)
    is_active = models.BooleanField(default=True)  # Corrigido aqui
    is_staff = models.BooleanField(default=False)
    criado_em = models.DateTimeField(auto_now_add=True)
    ultimo_login = models.DateTimeField(null=True, blank=True)

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ['nome']

    objects = MeuUserManager()

    def __str__(self):
        return self.email
