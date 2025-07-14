from rest_framework import serializers
from .models import User

class UserSerializer(serializers.ModelSerializer):
    senha = serializers.CharField(write_only=True)

    class Meta:
        model = User
        fields = ('id', 'nome', 'email', 'senha')

    def create(self, validated_data):
        senha = validated_data.pop('senha')
        user = User(**validated_data)
        user.set_password(senha)
        user.save()
        return user
