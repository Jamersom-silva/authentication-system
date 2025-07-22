from rest_framework import serializers
from django.contrib.auth.tokens import default_token_generator
from django.core.mail import send_mail
from django.utils.http import urlsafe_base64_encode
from django.utils.encoding import force_bytes
from .models import User

class UserSerializer(serializers.ModelSerializer):
    senha = serializers.CharField(write_only=True, required=True, style={'input_type': 'password'})

    class Meta:
        model = User
        fields = ('id', 'nome', 'email', 'senha')
        extra_kwargs = {
            'email': {'required': True},
            'nome': {'required': True},
        }

    def create(self, validated_data):
        senha = validated_data.pop('senha')
        user = User(**validated_data)
        user.set_password(senha)
        user.is_active = False  # Desativa até confirmação por email
        user.save()

        # Gera token e link de ativação
        token = default_token_generator.make_token(user)
        uid = urlsafe_base64_encode(force_bytes(user.pk))
        link_ativacao = f"http://localhost:8000/api/ativar/{uid}/{token}/"

        # Envia email de ativação
        send_mail(
            'Confirme seu cadastro',
            f'Clique no link para ativar sua conta: {link_ativacao}',
            'noreply@seudominio.com',
            [user.email],
            fail_silently=False,
        )
        return user
