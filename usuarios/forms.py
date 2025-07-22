from django import forms
from django.contrib.auth.forms import UserCreationForm, AuthenticationForm
from django.contrib.auth import get_user_model

User = get_user_model()

class RegistroForm(UserCreationForm):
    email = forms.EmailField(required=True)
    nome = forms.CharField(required=True)

    class Meta:
        model = User
        fields = ("nome", "email", "password1", "password2")

class LoginForm(AuthenticationForm):
    username = forms.EmailField(label="Email")  # Troca username por email
