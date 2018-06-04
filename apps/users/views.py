from django.shortcuts import render
from rest_framework import mixins
from rest_framework import viewsets
from .serializers import UserRegSerializer, UserDetailSerializer, UserLoginSerializer
from django.contrib.auth import get_user_model
from rest_framework import permissions
from rest_framework import status
from rest_framework.response import Response
from django.conf import settings
from datetime import datetime
from rest_framework.authentication import BaseAuthentication
from rest_framework.views import APIView
from django.contrib.auth.backends import ModelBackend
from django.db.models import Q
from django.utils import timezone
from django.contrib.auth.signals import user_logged_in
from .models import Users


class CustomBackend(ModelBackend):
    """
    自定义用户验证
    """

    def authenticate(self, username=None, password=None, **kwargs):
        try:
            user = User.objects.get(Q(username=username) | Q(email=username))
            if user.check_password(password):
                return user
        except Exception as e:
            return None


def get_token(username):
    # 需要获取token
    token = 'jwt 123abc'
    return token

User = get_user_model()
# Create your views here.


class UserInfo(APIView):
    '''
    获取用户个人信息
    '''
    # permission_classes = (permissions.IsAuthenticated(),)
    authentication_classes = ()

    def get_serializer(self, *args, **kwargs):
        """
        Return the serializer instance that should be used for validating and
        deserializing input, and for serializing output.
        """

        serializer_class = UserDetailSerializer

        return serializer_class(*args, **kwargs)

    def get(self, request, *arg, **kwargs):
        data = self.request.user
        serializer = self.get_serializer(data)
        return Response(serializer.data)


class UserSignUp(APIView):
    permission_classes = ()
    authentication_classes = ()

    def get_serializer(self, *args, **kwargs):
        """
        Return the serializer instance that should be used for validating and
        deserializing input, and for serializing output.
        """

        serializer_class = UserRegSerializer

        return serializer_class(*args, **kwargs)

    def post(self, request, *arg, **kwargs):
        serializer = self.get_serializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data)
        else:
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class UserLogin(APIView):
    permission_classes = ()
    authentication_classes = ()
    # serializer_class = UserLoginSerializer

    def get_serializer(self, *args, **kwargs):
        """
        Return the serializer instance that should be used for validating and
        deserializing input, and for serializing output.
        """

        serializer_class = UserLoginSerializer
        kwargs['context'] = {'request': self.request}

        return serializer_class(*args, **kwargs)

    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)

        if serializer.is_valid():
            return Response('SUCCESS')
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
