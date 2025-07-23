from django.contrib.auth import login, logout, get_user_model, authenticate
from django.contrib.auth.tokens import default_token_generator
from django.core.mail import send_mail
from django.utils.encoding import force_bytes, force_str
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.core.cache import cache
from django.shortcuts import render, redirect
from django.http import JsonResponse
from django.conf import settings
from django.contrib.auth.decorators import login_required

from rest_framework import generics, status
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework_simplejwt.tokens import RefreshToken

from .serializers import UserSerializer
from .forms import RegistroForm, LoginForm
from .auth_utils import login_required_jwt

import random
import secrets

User = get_user_model()


@login_required
def home_view(request):
    return render(request, 'usuarios/home.html')


def registro_view(request):
    if request.method == 'POST':
        form = RegistroForm(request.POST)
        if form.is_valid():
            user = form.save(commit=False)
            user.is_active = False  # Usuário precisa ativar via email
            user.save()
            # Aqui você pode enviar email de ativação
            return redirect('login')  # Redireciona para a tela de login
    else:
        form = RegistroForm()
    return render(request, 'usuarios/registro.html', {'form': form})


def login_view(request):
    form = LoginForm(request.POST or None)
    if request.method == 'POST' and form.is_valid():
        email = form.cleaned_data['email']
        password = form.cleaned_data['password']
        user = authenticate(request, email=email, password=password)
        if user is not None:
            login(request, user)
            return redirect(settings.LOGIN_REDIRECT_URL)
        else:
            form.add_error(None, "Email ou senha inválidos.")
    return render(request, 'usuarios/login.html', {'form': form})


def logout_view(request):
    logout(request)
    return redirect('login')


# API - Registro
class RegisterView(generics.CreateAPIView):
    serializer_class = UserSerializer
    permission_classes = [AllowAny]


# API - Logout (blacklist JWT)
class LogoutAPIView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        try:
            refresh_token = request.data.get("refresh")
            token = RefreshToken(refresh_token)
            token.blacklist()
            return Response({"detail": "Logout realizado com sucesso."}, status=status.HTTP_205_RESET_CONTENT)
        except Exception:
            return Response({"detail": "Token inválido ou ausente."}, status=status.HTTP_400_BAD_REQUEST)


# API - Dashboard protegido por JWT
@login_required_jwt
def dashboard_view(request):
    return JsonResponse({'message': f'Olá, {request.user.email}! Você está logado.'})


# API - Solicitação de redefinição de senha
class PasswordResetRequestAPIView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        email = request.data.get('email')
        if not email:
            return Response({'detail': 'Email é obrigatório.'}, status=status.HTTP_400_BAD_REQUEST)
        try:
            user = User.objects.get(email=email)
        except User.DoesNotExist:
            return Response({'detail': 'Se o email existir, enviaremos instruções.'})
        uid = urlsafe_base64_encode(force_bytes(user.pk))
        token = default_token_generator.make_token(user)
        link = request.build_absolute_uri(f'/api/password-reset-confirm/{uid}/{token}/')
        send_mail(
            'Redefinição de senha',
            f'Clique no link para redefinir sua senha: {link}',
            'noreply@seudominio.com',
            [email],
            fail_silently=False,
        )
        return Response({'detail': 'Email de redefinição enviado.'})


# API - Confirmação da redefinição de senha
class PasswordResetConfirmAPIView(APIView):
    permission_classes = [AllowAny]

    def post(self, request, uidb64, token):
        password = request.data.get('new_password')
        if not password:
            return Response({'detail': 'Senha nova é obrigatória.'}, status=status.HTTP_400_BAD_REQUEST)
        try:
            uid = force_str(urlsafe_base64_decode(uidb64))
            user = User.objects.get(pk=uid)
        except Exception:
            return Response({'detail': 'Token inválido.'}, status=status.HTTP_400_BAD_REQUEST)
        if not default_token_generator.check_token(user, token):
            return Response({'detail': 'Token inválido ou expirado.'}, status=status.HTTP_400_BAD_REQUEST)
        user.set_password(password)
        user.save()
        return Response({'detail': 'Senha redefinida com sucesso.'})


# API - Ativação de conta
class ActivateUserAPIView(APIView):
    permission_classes = [AllowAny]

    def get(self, request, uidb64, token):
        try:
            uid = force_str(urlsafe_base64_decode(uidb64))
            user = User.objects.get(pk=uid)
        except Exception:
            return Response({'detail': 'Link inválido.'}, status=status.HTTP_400_BAD_REQUEST)
        if user.is_active:
            return Response({'detail': 'Conta já ativada.'})
        if default_token_generator.check_token(user, token):
            user.is_active = True
            user.save()
            return Response({'detail': 'Conta ativada com sucesso.'})
        return Response({'detail': 'Link inválido ou expirado.'}, status=status.HTTP_400_BAD_REQUEST)


# Função utilitária para capturar IP do cliente
def get_client_ip(request):
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        ip = x_forwarded_for.split(',')[0]
    else:
        ip = request.META.get('REMOTE_ADDR')
    return ip


# API - Login com JWT e limitação de tentativas
class LoginAPIView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        ip = get_client_ip(request)
        attempts = cache.get(ip, 0)
        if attempts >= 5:
            return Response({'detail': 'Muitas tentativas. Tente novamente mais tarde.'}, status=status.HTTP_429_TOO_MANY_REQUESTS)

        email = request.data.get('email')
        password = request.data.get('password')

        user = authenticate(request, email=email, password=password)
        if user is None:
            cache.set(ip, attempts + 1, timeout=300)
            return Response({'detail': 'Credenciais inválidas.'}, status=status.HTTP_401_UNAUTHORIZED)

        cache.delete(ip)
        refresh = RefreshToken.for_user(user)
        return Response({
            'refresh': str(refresh),
            'access': str(refresh.access_token),
            'user': UserSerializer(user).data
        })


# API - Enviar código 2FA
class TwoFactorSendCodeAPIView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        user = request.user
        code = random.randint(100000, 999999)
        cache.set(f'2fa_{user.pk}', code, timeout=300)
        send_mail(
            'Seu código 2FA',
            f'Seu código de verificação é: {code}',
            'noreply@seudominio.com',
            [user.email],
            fail_silently=False,
        )
        return Response({'detail': 'Código 2FA enviado por email.'})


# API - Verificar código 2FA
class TwoFactorVerifyCodeAPIView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        user = request.user
        code = request.data.get('code')
        cached_code = cache.get(f'2fa_{user.pk}')
        if cached_code and secrets.compare_digest(str(cached_code), str(code)):
            cache.delete(f'2fa_{user.pk}')
            return Response({'detail': '2FA verificado com sucesso.'})
        return Response({'detail': 'Código inválido.'}, status=status.HTTP_400_BAD_REQUEST)
