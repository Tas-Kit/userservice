from copy import deepcopy
from .serializers import (UserRegSerializer,
                          UserDetailSerializer,
                          UserLoginSerializer,
                          UserUpdateSerializer,
                          UsersSerializers,
                          ResetPasswordSerializers,
                          SetPasswordSerializers,
                          ImageUploadSerializer,
                          ProfileUploadSerializer
                          )
from django.contrib.auth import get_user_model
from rest_framework import permissions, status, filters, mixins, viewsets
from rest_framework.response import Response
from django_filters.rest_framework import DjangoFilterBackend
from rest_framework.authentication import BaseAuthentication
from rest_framework.views import APIView
from django.contrib.auth.backends import ModelBackend
from django.db.models import Q
from rest_framework.pagination import PageNumberPagination
from django.core.mail import send_mail
from django.template.loader import get_template
from rest_framework_jwt.settings import api_settings
from userservice.utils import get_code
import validators
from rest_framework.parsers import FileUploadParser
from .services import PLATFORM


jwt_payload_handler = api_settings.JWT_PAYLOAD_HANDLER
jwt_encode_handler = api_settings.JWT_ENCODE_HANDLER
User = get_user_model()
platform = PLATFORM()


class CustomBackend(ModelBackend):
    """
    Auth
    """

    def authenticate(self, username=None, password=None, **kwargs):
        try:
            user = User.objects.get(Q(username=username) | Q(email=username))
            if user.check_password(password):
                return user
        except:
            return None


def get_token(user):
    payload = jwt_payload_handler(user)
    return jwt_encode_handler(payload)


class CookieAuthentication(BaseAuthentication):

    def authenticate(self, request):
        if 'HTTP_COOKIE' not in request._request.META:
            return None
        cookies = request._request.META['HTTP_COOKIE']
        cookies = cookies.replace(' ', '').split(';')
        for cookie in cookies:
            if cookie.startswith('uid='):
                uid = cookie.replace('uid=', '')
                user = User.objects.get(id=uid)
                return (user, None)
        return None


class ImageUploadParser(FileUploadParser):
    media_type = 'image/*'


class UploadImage(APIView):
    permission_classes = (permissions.IsAuthenticated,)
    authentication_classes = (CookieAuthentication,)
    parser_class = (ImageUploadParser,)

    def get_serializer(self, *args, **kwargs):
        """
        Return the serializer instance that should be used for validating and
        deserializing input, and for serializing output.
        """
        serializer_class = ImageUploadSerializer
        return serializer_class(*args, **kwargs)

    def post(self, request, format=None):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        result = serializer.save()
        return Response(result, status=status.HTTP_201_CREATED)


class UploadProfile(APIView):
    permission_classes = (permissions.IsAuthenticated,)
    authentication_classes = (CookieAuthentication,)
    parser_class = (ImageUploadParser,)

    def get_serializer(self, *args, **kwargs):
        """
        Return the serializer instance that should be used for validating and
        deserializing input, and for serializing output.
        """
        serializer_class = ProfileUploadSerializer
        kwargs['context'] = {
            'request': self.request
        }
        return serializer_class(*args, **kwargs)

    def get_serializer_context(self):
        """
        Extra context provided to the serializer class.
        """
        return {
            'request': self.request
        }

    def post(self, request, format=None):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        result = serializer.save()
        return Response(result, status=status.HTTP_201_CREATED)


class UserInfo(APIView):
    """
    list get personal info
    create modify personal info
    """

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
        userinfo = deepcopy(serializer.data)
        userinfo['uid'] = userinfo['id']
        del userinfo['id']
        return Response(userinfo)

    def post(self, request, *arg, **kwargs):
        user = self.request.user
        serializer = self.get_serializer(data=request.data)
        if serializer.is_valid(raise_exception=True):
            for name, value in serializer.data.items():
                if value:
                    if name == 'password':
                        user.set_password(value)
                    else:
                        setattr(user, name, value)
            user.save()
            return Response('SUCCESS')
        else:
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class UserSignUp(APIView):
    """
    User sign up
    """

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
            user = User.objects.get(Q(username=request.data['username']))
            response = Response(serializer.data)
            response.set_cookie(api_settings.JWT_AUTH_COOKIE, get_token(user))
            return response
        else:
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class UserLogin(APIView):
    """
    user login
    """

    permission_classes = ()
    authentication_classes = ()

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
            platform_root_key = platform.get_platform_root_key(request.user.id)
            response = Response(platform_root_key)
            response.set_cookie(api_settings.JWT_AUTH_COOKIE, get_token(request.user))
            return response
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class UsersPage(PageNumberPagination):
    """
    paging
    """

    page_size = 20
    page_size_query_param = 'page_size'
    page_query_param = "page"
    max_page_size = 50


class UsersViewSet(
        mixins.ListModelMixin,
        mixins.RetrieveModelMixin,
        viewsets.GenericViewSet):
    """
    Users lookup
    """

    serializer_class = UsersSerializers
    pagination_class = UsersPage

    filter_backends = (DjangoFilterBackend, filters.SearchFilter)

    filter_fields = ('username', 'email')
    search_fields = filter_fields

    def get_queryset(self):
        ids = self.request.GET.getlist('uid', [])
        validate_uuid = [i for i in ids if validators.uuid(i)]
        usernames = self.request.GET.getlist('username')
        querysets = User.objects.filter(Q(id__in=validate_uuid) | Q(username__in=usernames)).order_by('date_joined')
        [setattr(item, 'uid', item.id) for item in querysets]
        return querysets


class ResetPassword(APIView):
    """
    reset password get code
    """

    permission_classes = ()
    authentication_classes = ()

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
            email = data.validated_data.get('email')
            code = get_code(email)
            t = get_template('email.html')
            html = t.render({'code': code})
            try:
                send_mail(subject='Reset Password',
                                  from_email='no-reply@tas-kit.com',
                                  message='',
                                  recipient_list=[email, ],
                                  html_message=html,
                                  fail_silently=False)
                return Response('SUCCESS')
            except Exception as e:
                print(e)
                return Response({'non_field_errors': 'Failed to send mail'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        else:
            return Response(data.errors, status=status.HTTP_400_BAD_REQUEST)


class SetPassword(APIView):
    """
    Reset password
    """

    permission_classes = ()
    authentication_classes = ()

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
