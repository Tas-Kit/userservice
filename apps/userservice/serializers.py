from rest_framework import serializers
from django.contrib.auth import get_user_model
from rest_framework.validators import UniqueValidator
from django.contrib.auth import authenticate
from django.utils.translation import ugettext as _
from datetime import datetime
from datetime import timedelta
from .models import VerifyCode


User = get_user_model()


class UserDetailSerializer(serializers.ModelSerializer):
    """
    用户详情序列化类
    """
    class Meta:
        model = User
        fields = ("username", 'first_name', 'last_name', "gender", "birthday", "email", "phone", 'area_code', 'address')


class UserUpdateSerializer(serializers.ModelSerializer):
    username = serializers.CharField(label='用户名', help_text='用户名', required=False, allow_blank=True, validators=[
                                     UniqueValidator(queryset=User.objects.all(), message="用户已经存在")])
    email = serializers.EmailField(label='邮箱', help_text='邮箱', required=False, allow_blank=True, validators=[
                                   UniqueValidator(queryset=User.objects.all(), message="邮箱已注册")])
    password = serializers.CharField(label='密码', help_text='密码', allow_blank=True, required=False)

    class Meta:
        model = User
        fields = ("username", 'password', 'first_name', 'last_name', "gender",
                  "birthday", "email", "phone", 'area_code', 'address')


class UserRegSerializer(serializers.ModelSerializer):
    username = serializers.CharField(label="用户名", help_text="用户名", required=True,
                                     validators=[UniqueValidator(queryset=User.objects.all(), message="用户已经存在")])

    password = serializers.CharField(
        help_text="密码", label="密码", write_only=True, required=True,
    )

    email = serializers.EmailField(label='邮箱', help_text='邮箱', validators=[
                                   UniqueValidator(queryset=User.objects.all(), message="邮箱已注册")])

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
    username = serializers.CharField(label="用户名或邮箱", help_text="用户名或邮箱", required=True, allow_blank=False)
    password = serializers.CharField(help_text="密码", label="密码", write_only=True)

    def validate(self, attrs):
        credentials = {
            'username': attrs.get('username'),
            'password': attrs.get('password')
        }

        if all(credentials.values()):
            # print(credentials)
            user = authenticate(**credentials)  # 官方验证
            # print(user)
            self.context.get('request').user = user

            if user:
                if not user.is_active:
                    msg = _('User account is disabled.')
                    raise serializers.ValidationError(msg)

                return {'username': credentials.get('username')}
            else:
                msg = _('账号或密码错误')
                raise serializers.ValidationError(msg)
        else:
            msg = _('Must include "{username_field}" and "password".')
            msg = msg.format(username_field=self.username_field)
            raise serializers.ValidationError(msg)


class UsersSerializers(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ('id', 'username', 'first_name', 'last_name',
                  'email', 'birthday', 'gender', 'phone', 'address')


class ResetPasswordSerializers(serializers.Serializer):
    email = serializers.EmailField(label='邮箱', help_text='邮箱')

    def validate_email(self, email):
        '''
        验证邮箱是否存在
        '''
        try:
            User.objects.get(email=email)
        except User.DoesNotExist:
            raise serializers.ValidationError("该邮箱不存在")
        else:
            return email


class SetPasswordSerializers(serializers.Serializer):
    code = serializers.CharField(label='编码', max_length=50)
    password = serializers.CharField(help_text="密码", label="密码", write_only=True)

    def validate_code(self, code):
        code = VerifyCode.objects.filter(code=code).order_by("-add_time")
        if code:
            last_code = code[0]
            ten_mintes_ago = datetime.now() - timedelta(hours=0, minutes=10, seconds=0)
            if ten_mintes_ago > last_code.add_time:
                raise serializers.ValidationError("重置密码链接过期,请重新申请")
            self.context['email'] = last_code.email
            return code
        else:
            raise serializers.ValidationError("未重置密码")

    def validate(self, attrs):
        email = self.context.get('email')
        try:
            user = User.objects.get(email=email)
        except User.DoesNotExist:
            raise serializers.ValidationError('用户不存在')
        else:
            user.set_password(attrs['password'])
            VerifyCode.objects.filter(email=email).delete()
            return attrs
