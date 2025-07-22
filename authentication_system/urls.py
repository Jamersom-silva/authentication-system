from django.contrib import admin
from django.urls import path, include
from usuarios import views as usuarios_views
from rest_framework_simplejwt.views import TokenRefreshView

urlpatterns = [
    path('admin/', admin.site.urls),

    # Rotas para views tradicionais (formulários)
    path('', usuarios_views.login_view, name='login'),
    path('home/', usuarios_views.home_view, name='home'),       
    path('registro/', usuarios_views.registro_view, name='registro'),
    path('logout/', usuarios_views.logout_view, name='logout'),

    # Rotas para API REST (JWT, autenticação, etc)
    path('api/register/', usuarios_views.RegisterView.as_view(), name='api_register'),
    path('api/login/', usuarios_views.LoginAPIView.as_view(), name='api_login'),
    path('api/logout/', usuarios_views.LogoutAPIView.as_view(), name='api_logout'),

    # Renovação do token JWT usando refresh token
    path('api/token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),

    # Redefinição de senha via email
    path('api/password-reset/', usuarios_views.PasswordResetRequestAPIView.as_view(), name='password_reset'),
    path('api/password-reset-confirm/<uidb64>/<token>/', usuarios_views.PasswordResetConfirmAPIView.as_view(), name='password_reset_confirm'),

    # Ativação de conta via email
    path('api/ativar/<uidb64>/<token>/', usuarios_views.ActivateUserAPIView.as_view(), name='activate_user'),

    # Autenticação de dois fatores (2FA)
    path('api/2fa/send/', usuarios_views.TwoFactorSendCodeAPIView.as_view(), name='2fa_send'),
    path('api/2fa/verify/', usuarios_views.TwoFactorVerifyCodeAPIView.as_view(), name='2fa_verify'),

    # Social Auth (OAuth)
    path('oauth/', include('social_django.urls', namespace='social')),
]
