from django.contrib import admin
from django.urls import path, include
from usuarios import views as usuarios_views

urlpatterns = [
    path('admin/', admin.site.urls),
    path('', usuarios_views.home_view, name='home'),
    path('registro/', usuarios_views.registro_view, name='registro'),
    path('login/', usuarios_views.login_view, name='login'),
    path('logout/', usuarios_views.logout_view, name='logout'),
    path('oauth/', include('social_django.urls', namespace='social')),
    path('api/register/', usuarios_views.RegisterView.as_view(), name='api_register'),
]
