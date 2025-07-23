from django import forms
from django.contrib.auth.forms import UserCreationForm
from django.contrib.auth import get_user_model

User = get_user_model()

class RegistroForm(UserCreationForm):
    email = forms.EmailField(required=True)
    nome = forms.CharField(max_length=100, required=True)  # Campo adicionado

    class Meta:
        model = User
        fields = ['username', 'nome', 'email', 'password1', 'password2']


class LoginForm(forms.Form):
    email = forms.EmailField(label='Email', max_length=255)
    password = forms.CharField(label='Senha', widget=forms.PasswordInput)
