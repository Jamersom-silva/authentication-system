import jwt
from django.conf import settings
from django.contrib.auth import get_user_model
from django.http import JsonResponse
from functools import wraps



User = get_user_model()

def decode_jwt_token(token):
    try:
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=["HS256"])
        user_id = payload.get('user_id')
        if user_id is None:
            return None
        return User.objects.get(id=user_id)
    except (jwt.ExpiredSignatureError, jwt.DecodeError, User.DoesNotExist):
        return None
def login_required_jwt(view_func):
    @wraps(view_func)
    def _wrapped_view(request, *args, **kwargs):
        token = None

        # Busca o token do header Authorization: Bearer <token>
        auth_header = request.headers.get('Authorization')
        if auth_header and auth_header.startswith("Bearer "):
            token = auth_header.split(" ")[1]

        # Ou do cookie se preferir
        if not token:
            token = request.COOKIES.get('jwt')

        user = decode_jwt_token(token)
        if user is None:
            return JsonResponse({'error': 'Authentication required'}, status=401)

        # Associa o usuário à request
        request.user = user
        return view_func(request, *args, **kwargs)

    return _wrapped_view