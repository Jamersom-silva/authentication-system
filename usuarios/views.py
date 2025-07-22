from django.contrib.auth import login, logout, get_user_model
from django.contrib.auth.tokens import default_token_generator
from django.core.mail import send_mail
from django.utils.encoding import force_bytes, force_str
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.core.cache import cache
from rest_framework import generics, status
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework_simplejwt.tokens import RefreshToken
from django.http import JsonResponse
from .serializers import UserSerializer
from .forms import RegistroForm, LoginForm
from .auth_utils import login_required_jwt  # seu decorador JWT
import random
from django.shortcuts import render, redirect

User = get_user_model()

# ----- Registro e Login com formulário Django (tradicional) -----

def registro_view(request):
    if request.method == 'POST':
        form = RegistroForm(request.POST)
        if form.is_valid():
            user = form.save()
            login(request, user)
            return redirect('home')
    else:
        form = RegistroForm()
    return render(request, 'usuarios/registro.html', {'form': form})

def login_view(request):
    if request.method == 'POST':
        form = LoginForm(request, data=request.POST)
        if form.is_valid():
            user = form.get_user()
            login(request, user)
            return redirect('home')
    else:
        form = LoginForm()
    return render(request, 'usuarios/login.html', {'form': form})

def logout_view(request):
    logout(request)
    return redirect('login')

@login_required_jwt
def dashboard_view(request):
    return JsonResponse({'message': f'Olá, {request.user.username}! Você está logado.'})

# ----- API Registration (DRF) -----

class RegisterView(generics.CreateAPIView):
    serializer_class = UserSerializer
    permission_classes = [AllowAny]

# ----- Logout API com blacklist JWT -----

class LogoutAPIView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        try:
            refresh_token = request.data["refresh"]
            token = RefreshToken(refresh_token)
            token.blacklist()
            return Response({"detail": "Logout realizado com sucesso."}, status=status.HTTP_205_RESET_CONTENT)
        except Exception:
            return Response({"detail": "Token inválido ou ausente."}, status=status.HTTP_400_BAD_REQUEST)

# ----- Redefinição de senha via email -----

class PasswordResetRequestAPIView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        email = request.data.get('email')
        if not email:
            return Response({'detail': 'Email é obrigatório.'}, status=status.HTTP_400_BAD_REQUEST)
        try:
            user = User.objects.get(email=email)
        except User.DoesNotExist:
            # Resposta genérica para segurança
            return Response({'detail': 'Se o email existir, enviaremos instruções.'})
        uid = urlsafe_base64_encode(force_bytes(user.pk))
        token = default_token_generator.make_token(user)
        link = f"http://localhost:8000/api/password-reset-confirm/{uid}/{token}/"
        send_mail(
            'Redefinição de senha',
            f'Clique no link para redefinir sua senha: {link}',
            'noreply@seudominio.com',
            [email],
            fail_silently=False,
        )
        return Response({'detail': 'Email de redefinição enviado.'})

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

# ----- Ativação de conta por email -----

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
        else:
            return Response({'detail': 'Link inválido ou expirado.'}, status=status.HTTP_400_BAD_REQUEST)

# ----- Limite de tentativas de login (exemplo simples) -----

def get_client_ip(request):
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        ip = x_forwarded_for.split(',')[0]
    else:
        ip = request.META.get('REMOTE_ADDR')
    return ip

class LoginAPIView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        ip = get_client_ip(request)
        attempts = cache.get(ip, 0)
        if attempts >= 5:
            return Response({'detail': 'Muitas tentativas. Tente novamente mais tarde.'}, status=status.HTTP_429_TOO_MANY_REQUESTS)

        # Aqui você coloca sua lógica de autenticação JWT
        # Exemplo fictício:
        email = request.data.get('email')
        password = request.data.get('password')

        try:
            user = User.objects.get(email=email)
            if not user.check_password(password):
                raise Exception()
        except Exception:
            cache.set(ip, attempts + 1, timeout=300)  # bloqueio 5 min
            return Response({'detail': 'Credenciais inválidas.'}, status=status.HTTP_401_UNAUTHORIZED)

        cache.delete(ip)
        # Aqui gere seu JWT e retorne para o usuário
        refresh = RefreshToken.for_user(user)
        return Response({
            'refresh': str(refresh),
            'access': str(refresh.access_token),
        })

# ----- 2FA simples via email -----

class TwoFactorSendCodeAPIView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        user = request.user
        code = random.randint(100000, 999999)
        cache.set(f'2fa_{user.pk}', code, timeout=300)  # válido 5 minutos
        send_mail(
            'Seu código 2FA',
            f'Seu código de verificação é: {code}',
            'noreply@seudominio.com',
            [user.email],
            fail_silently=False,
        )
        return Response({'detail': 'Código 2FA enviado por email.'})

class TwoFactorVerifyCodeAPIView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        user = request.user
        code = request.data.get('code')
        cached_code = cache.get(f'2fa_{user.pk}')
        if cached_code and str(cached_code) == str(code):
            cache.delete(f'2fa_{user.pk}')
            return Response({'detail': '2FA verificado com sucesso.'})
        return Response({'detail': 'Código inválido.'}, status=status.HTTP_400_BAD_REQUEST)
