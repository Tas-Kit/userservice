from rest_framework import mixins
from rest_framework import viewsets
from .serializers import (UserRegSerializer, UserDetailSerializer, UserLoginSerializer, UserUpdateSerializer,
                          UsersSerializers, ResetPasswordSerializers, SetPasswordSerializers
                          )
from django.contrib.auth import get_user_model
from rest_framework import permissions
from rest_framework import status
from rest_framework.response import Response
from django_filters.rest_framework import DjangoFilterBackend
from rest_framework import filters
from rest_framework.authentication import BaseAuthentication
from rest_framework.views import APIView
from django.contrib.auth.backends import ModelBackend
from django.db.models import Q
from rest_framework.pagination import PageNumberPagination
from .models import VerifyCode
from django.core.mail import send_mail
import uuid
from django.template.loader import get_template
from django.conf import settings

User = get_user_model()


class CustomBackend(ModelBackend):
    """
    自定义登陆验证
    """

    def authenticate(self, username=None, password=None, **kwargs):
        try:
            user = User.objects.get(Q(username=username) | Q(email=username))
            print(user)
            if user.check_password(password):
                return user
        except:
            return None


def get_token(username):
    # 需要获取token
    token = 'jwt 123abc'
    return token


class CookieAuthentication(BaseAuthentication):
    def authenticate(self, request):
        # 根据uuid获取user

        cookie = request._request.META.get('HTTP_COOKIE')
        user = None
        if cookie:
            cookie_str = cookie.replace(' ', '')
            if 'uid' in cookie_str:
                uid = cookie_str.replace('uid=', '')
                user = User.objects.get(id=uid)

        if not user:
            return None
        else:
            return (user, None)


class UserInfo(APIView):
    '''
    list 获取用户个人信息
    create 修改个人信息
    '''
    permission_classes = (permissions.IsAuthenticated,)
    authentication_classes = (CookieAuthentication,)

    def get_serializer(self, *args, **kwargs):
        """
        Return the serializer instance that should be used for validating and
        deserializing input, and for serializing output.
        """
        kwargs['context'] = self.get_serializer_context()
        return UserUpdateSerializer(*args, **kwargs)

    def get_serializer_context(self):
        """
        Extra context provided to the serializer class.
        """
        return {
            'request': self.request,
            'format': self.format_kwarg,
            'view': self
        }

    def get(self, request, *arg, **kwargs):
        data = self.request.user
        serializer = UserDetailSerializer(data)
        return Response(serializer.data)

    def post(self, request, *arg, **kwargs):
        user = self.request.user
        serializer = self.get_serializer(data=request.data)
        if serializer.is_valid(raise_exception=True):
            for name, value in serializer.data.items():
                if value:
                    if name == 'password':
                        print('mimao change')
                        user.set_password(value)
                    else:
                        setattr(user, name, value)
            user.save()
            return Response('SUCCESS')
        else:
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class UserSignUp(APIView):
    '''
    用户注册
    '''
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
        if serializer.is_valid(raise_exception=True):
            serializer.save()
            return Response(serializer.data)
        else:
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class UserLogin(APIView):
    '''
    用户登入
    '''
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

        if serializer.is_valid(raise_exception=True):
            return Response('SUCCESS')
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class UsersPage(PageNumberPagination):
    '''
    分页设置
    '''
    page_size = 20
    page_size_query_param = 'page_size'
    page_query_param = "page"
    max_page_size = 50


class UsersViewSet(
        mixins.ListModelMixin,
        mixins.RetrieveModelMixin,
        viewsets.GenericViewSet):
    '''
    非个人用户查询
    '''

    serializer_class = UsersSerializers
    queryset = User.objects.all()
    # authentication_classes = ()
    pagination_class = UsersPage

    filter_backends = (DjangoFilterBackend, filters.SearchFilter)

    filter_fields = ('id', 'username', 'phone', 'email')
    search_fields = filter_fields


class ResetPassword(APIView):
    '''
    重置密码 获取 code
    '''

    def get_serializer(self, *args, **kwargs):
        """
        Return the serializer instance that should be used for validating and
        deserializing input, and for serializing output.
        """
        serializer_class = ResetPasswordSerializers
        return serializer_class(*args, **kwargs)

    def post(self, request, *arg, **kwargs):
        data = self.get_serializer(data=request.data)
        if data.is_valid(raise_exception=True):
            email = data.data.get('email')
            code = uuid.uuid4()
            obj = VerifyCode(email=email, code=code)
            obj.save()
            t = get_template('email.html')
            html = t.render({'code': code})

            send_mail(subject='重置密码',
                              from_email=settings.EMAIL_HOST_USER,
                              message='',
                              recipient_list=[email, ],
                              html_message=html,
                              fail_silently=False)
            return Response('SUCCESS')
        else:
            Response(data.errors, status=status.HTTP_400_BAD_REQUEST)


class SetPassword(APIView):
    '''
    重置密码
    '''

    def get_serializer(self, *args, **kwargs):
        """
        Return the serializer instance that should be used for validating and
        deserializing input, and for serializing output.
        """
        serializer_class = SetPasswordSerializers
        return serializer_class(*args, **kwargs)

    def post(self, request, *arg, **kwargs):
        data = self.get_serializer(data=request.data)
        if data.is_valid(raise_exception=True):
            return Response('SUCCESS')
        else:
            Response(data.errors, status=status.HTTP_400_BAD_REQUEST)
