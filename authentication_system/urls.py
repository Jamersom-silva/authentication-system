from django.contrib import admin
from django.urls import path, include
from usuarios import views as usuarios_views

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

    path('api/token/refresh/', 
         # Se você estiver usando o TokenRefreshView oficial do SimpleJWT
         # importe e use ele aqui:
         # from rest_framework_simplejwt.views import TokenRefreshView
         # path('api/token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),

         usuarios_views.TokenRefreshAPIView.as_view(), name='token_refresh'),

    path('api/password-reset/', usuarios_views.PasswordResetRequestAPIView.as_view(), name='password_reset'),
    path('api/password-reset-confirm/<uidb64>/<token>/', usuarios_views.PasswordResetConfirmAPIView.as_view(), name='password_reset_confirm'),
    path('api/ativar/<uidb64>/<token>/', usuarios_views.ActivateUserAPIView.as_view(), name='activate_user'),

    path('api/2fa/send/', usuarios_views.TwoFactorSendCodeAPIView.as_view(), name='2fa_send'),
    path('api/2fa/verify/', usuarios_views.TwoFactorVerifyCodeAPIView.as_view(), name='2fa_verify'),

    # Social Auth
    path('oauth/', include('social_django.urls', namespace='social')),
]
