from rest_framework import serializers
from django.contrib.auth import get_user_model
from rest_framework.validators import UniqueValidator
from django.contrib.auth import authenticate
from django.utils.translation import ugettext as _
from .utils import process_image, upload
import uuid
import re
from userservice.utils import verify_code


User = get_user_model()


def validate_password(password):
    """
    verify password must have num and alphabet

    """
    if not re.findall('[a-zA-Z]+', password) or not re.findall('[0-9]+', password):
        raise serializers.ValidationError('password must include Numbers and letters', code=411)
    return password


class UserDetailSerializer(serializers.ModelSerializer):
    """
    user serializer
    """

    class Meta:
        model = User
        fields = ('id', "username", 'first_name', 'last_name', "gender", "birthday", "email", "phone", 'area_code', 'address')


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
        return validate_password(password)


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
        return validate_password(password)

    def create(self, validated_data):
        user = super(UserRegSerializer, self).create(validated_data=validated_data)
        user.set_password(validated_data["password"])
        user.is_active = True
        user.save()
        return user

    class Meta:
        model = User
        fields = ("username", "password", 'email')


class ProfileUploadSerializer(serializers.Serializer):
    image = serializers.FileField(label="The image to upload", required=True)

    def create(self, validate_data):
        user = self.context.get('request').user
        image = validate_data['image']
        upload('user/{0}/profile.jpg'.format(user.id), image)
        return 'SUCCESS'

    def validate_image(self, image):
        return process_image(image)


class ImageUploadSerializer(serializers.Serializer):
    path = serializers.CharField(label="Path of the image", required=True, allow_blank=False)
    image = serializers.FileField(label="The image to upload", required=True)

    valid_file_path = {
        'task': {
            'icon': True,
            'description': {
                'jpg': True
            }
        },
        'step': {
            'icon': True,
            'description': {
                'jpg': True
            }
        },
    }

    def create(self, validate_data):
        iid = str(uuid.uuid4())
        path = validate_data['path']
        image = validate_data['image']
        upload('{0}/{1}.jpg'.format(path, iid), image)
        return {
            'iid': iid
        }

    def validate_path(self, path):
        path = path.split('/')
        temp_item = self.valid_file_path
        new_path = []
        for item in path:
            if item is not None and item != '':
                if item in temp_item:
                    temp_item = temp_item[item]
                    new_path.append(item)
                else:
                    temp_item = False
                    break
        new_path = '/'.join(new_path)
        if temp_item is not True:
            raise serializers.ValidationError('Incorrect upload file path: {0}'.format(new_path), code=410)
        return new_path

    def validate_image(self, image):
        return process_image(image)


class UserLoginSerializer(serializers.Serializer):
    username = serializers.CharField(label="username or email", help_text="username or email", required=True, allow_blank=False)
    password = serializers.CharField(help_text="password", label="password", write_only=True)

    def validate(self, attrs):
        if all(attrs.values()):
            user = authenticate(**attrs)
            self.context.get('request').user = user

            if user:
                if not user.is_active:
                    msg = _('User account is disabled.')
                    raise serializers.ValidationError(msg, code=411)

                return {'username': attrs.get('username')}
            else:
                msg = _('username/email or password error')
                raise serializers.ValidationError(msg, code=412)
        else:
            msg = _('Must include "{username_field}" and "password".')
            msg = msg.format(username_field=self.username_field)
            raise serializers.ValidationError(msg, code=413)


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
        """
        validate email existes
        """
        try:
            User.objects.get(email=email)
        except User.DoesNotExist:
            raise serializers.ValidationError("Email doesn't exist")
        else:
            return email


class SetPasswordSerializers(serializers.Serializer):
    code = serializers.CharField(label='code', max_length=6)
    email = serializers.CharField(label='email', max_length=100)
    password = serializers.CharField(help_text="password", label="password", write_only=True, min_length=8, required=True,
                                     error_messages={
                                         'required': 'Please enter the username',
                                         'min_length': 'Password length must not be less than 8 characters'
                                     })

    def validate_password(self, password):
        return validate_password(password)

    def validate(self, attrs):
        try:
            user = User.objects.get(email=attrs['email'])
        except User.DoesNotExist:
            raise serializers.ValidationError('Unable to find user with given Email.')
        if verify_code(attrs['email'], attrs['code']):
            password = attrs['password']
            user.set_password(password)
            user.save()
            return attrs
        else:
            raise serializers.ValidationError('Invalid verification code.')
