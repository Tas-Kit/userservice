from rest_framework import serializers
from django.contrib.auth import get_user_model
from rest_framework.validators import UniqueValidator
from django.contrib.auth import authenticate
from django.utils.translation import ugettext as _
from datetime import datetime
from datetime import timedelta
from .models import VerifyCode
import re


User = get_user_model()


def validate_password(password):
    '''
    verify password must have num and alphabet

    '''
    if not re.findall('[a-zA-Z]+', password):
        return False

    if not re.findall('[0-9]+', password):
        print('num')
        return False

    return True


class UserDetailSerializer(serializers.ModelSerializer):
    """
    user serializer
    """
    class Meta:
        model = User
        fields = ("username", 'first_name', 'last_name', "gender", "birthday", "email", "phone", 'area_code', 'address')


class UserUpdateSerializer(serializers.ModelSerializer):
    username = serializers.CharField(label='user name', help_text='user name', required=False, allow_blank=True, validators=[
                                     UniqueValidator(queryset=User.objects.all(), message="That username is already exists")],
                                     )
    email = serializers.EmailField(label='email', help_text='email', required=False, allow_blank=True, validators=[
                                   UniqueValidator(queryset=User.objects.all(), message="That email is already exists")],
                                   )
    password = serializers.CharField(label='password', help_text='password', allow_blank=True, required=False, min_length=8,
                                     error_messages={
                                         'min_length': 'Password length must not be less than 8 characters'
                                     })

    class Meta:
        model = User
        fields = ("username", 'password', 'first_name', 'last_name', "gender",
                  "birthday", "email", "phone", 'area_code', 'address')

    def validate_password(self, password):
        if not validate_password(password):
            raise serializers.ValidationError('password must include Numbers and letters')
        return password


class UserRegSerializer(serializers.ModelSerializer):
    username = serializers.CharField(label="username", help_text="username", required=True,
                                     validators=[
                                         UniqueValidator(queryset=User.objects.all(),
                                                         message="That username is already exists")],
                                     error_messages={
                                         "blank": "Please enter the username",
                                         "required": "Please enter the username",
                                     })

    password = serializers.CharField(
        help_text="password", label="password", write_only=True, required=True, min_length=8,
        error_messages={
            'blank': 'Please enter the password',
            'required': 'Please enter the password',
            'min_length': 'Password length must not be less than 8 characters'
        }
    )

    email = serializers.EmailField(label='email', help_text='email', validators=[
                                   UniqueValidator(queryset=User.objects.all(), message="That email is already exists")],
                                   error_messages={
                                   'blank': 'Please enter the email',
                                   'required': 'Please enter the email'
                                   })

    def validate_password(self, password):
        if not validate_password(password):
            raise serializers.ValidationError('password must include Numbers and letters')
        return password

    def create(self, validated_data):
        user = super(UserRegSerializer, self).create(validated_data=validated_data)
        user.set_password(validated_data["password"])
        user.is_active = True
        user.save()
        return user

    class Meta:
        model = User
        fields = ("username", "password", 'email')


class UserLoginSerializer(serializers.Serializer):
    username = serializers.CharField(label="username or email", help_text="username or email", required=True, allow_blank=False)
    password = serializers.CharField(help_text="password", label="password", write_only=True)

    def validate(self, attrs):
        credentials = {
            'username': attrs.get('username'),
            'password': attrs.get('password')
        }

        if all(credentials.values()):
            user = authenticate(**credentials)
            self.context.get('request').user = user

            if user:
                if not user.is_active:
                    msg = _('User account is disabled.')
                    raise serializers.ValidationError(msg)

                return {'username': credentials.get('username')}
            else:
                msg = _('username/email or password error')
                raise serializers.ValidationError(msg)
        else:
            msg = _('Must include "{username_field}" and "password".')
            msg = msg.format(username_field=self.username_field)
            raise serializers.ValidationError(msg)


class UsersSerializers(serializers.ModelSerializer):
    uid = serializers.UUIDField(format='hex_verbose')

    class Meta:
        setattr(User, 'uid', User.id)
        model = User
        fields = ('uid', 'username', 'first_name', 'last_name',
                  'birthday', 'gender', 'phone', 'address')


class ResetPasswordSerializers(serializers.Serializer):
    email = serializers.EmailField(label='email', help_text='email')

    def validate_email(self, email):
        '''
        validate email existes
        '''
        try:
            User.objects.get(email=email)
        except User.DoesNotExist:
            raise serializers.ValidationError("Email doesn't exist")
        else:
            return email


class SetPasswordSerializers(serializers.Serializer):
    code = serializers.CharField(label='code', max_length=50)
    password = serializers.CharField(help_text="password", label="password", write_only=True, min_length=8, required=True,
                                     error_messages={
                                         'required': 'Please enter the username',
                                         'min_length': 'Password length must not be less than 8 characters'
                                     })

    def validate_code(self, code):
        code = VerifyCode.objects.filter(code=code).order_by("-add_time")
        if code:
            last_code = code[0]
            ten_mintes_ago = datetime.now() - timedelta(hours=0, minutes=10, seconds=0)
            if ten_mintes_ago > last_code.add_time:
                raise serializers.ValidationError("Hyperlink expiration,Please apply again")
            self.context['email'] = last_code.email
            return code
        else:
            raise serializers.ValidationError("Hyperlink invalid,Please apply again")

    def validate_password(self, password):
        if not validate_password(password):
            raise serializers.ValidationError('password must include Numbers and letters')
        return password

    def validate(self, attrs):
        email = self.context.get('email')
        try:
            user = User.objects.get(email=email)
        except User.DoesNotExist:
            raise serializers.ValidationError('Hyperlink invalid,Please apply again')
        else:
            password = attrs['password']
            user.set_password(password)
            user.save()
            VerifyCode.objects.filter(email=email).delete()
            return attrs
