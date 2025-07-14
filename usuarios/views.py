from django.shortcuts import render, redirect
from django.contrib.auth import login, logout
from .forms import RegistroForm, LoginForm
from .serializers import UserSerializer
from rest_framework import generics
from rest_framework.permissions import AllowAny
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from rest_framework.permissions import IsAuthenticated
from rest_framework_simplejwt.tokens import RefreshToken


class RegisterView(generics.CreateAPIView):
    serializer_class = UserSerializer
    permission_classes = [AllowAny]

# View para página de registro com formulário HTML
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

# View para página de login com formulário HTML
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

# View para logout
def logout_view(request):
    logout(request)
    return redirect('login')

# View para home (evita erro de importação)
def home_view(request):
    return render(request, 'usuarios/home.html')

class LogoutAPIView(APIView):
    permission_classes = (IsAuthenticated,)

    def post(self, request):
        try:
            refresh_token = request.data["refresh"]
            token = RefreshToken(refresh_token)
            token.blacklist()
            return Response({"detail": "Logout realizado com sucesso."}, status=status.HTTP_205_RESET_CONTENT)
        except Exception as e:
            return Response({"detail": "Token inválido ou ausente."}, status=status.HTTP_400_BAD_REQUEST)