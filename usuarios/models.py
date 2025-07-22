from django.contrib.auth.models import AbstractBaseUser, BaseUserManager, PermissionsMixin
from django.db import models

class MeuUserManager(BaseUserManager):
    def create_user(self, email, password=None, nome=None, **extra_fields):
        if not email:
            raise ValueError('Email obrigatório')
        email = self.normalize_email(email)
        user = self.model(email=email, nome=nome, **extra_fields)
        user.set_password(password)
        user.save()
        return user

    def create_superuser(self, email, password, nome=None, **extra_fields):
        user = self.create_user(email, password, nome=nome, **extra_fields)
        user.is_staff = True
        user.is_superuser = True
        user.is_active = True
        user.save()
        return user

class User(AbstractBaseUser, PermissionsMixin):
    email = models.EmailField(unique=True)
    nome = models.CharField(max_length=100)
    is_active = models.BooleanField(default=False)  # Desativado até ativação por email
    is_staff = models.BooleanField(default=False)
    criado_em = models.DateTimeField(auto_now_add=True)
    ultimo_login = models.DateTimeField(null=True, blank=True)

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ['nome']

    objects = MeuUserManager()

    def __str__(self):
        return self.email
