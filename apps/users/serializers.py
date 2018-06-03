import re
from rest_framework import serializers
from django.contrib.auth import get_user_model
from rest_framework.validators import UniqueTogetherValidator,UniqueValidator
from django.contrib.auth import authenticate
from django.utils.translation import ugettext as _



User = get_user_model()

class UserDetailSerializer(serializers.ModelSerializer):
    """
    用户详情序列化类
    """
    class Meta:
        model = User
        fields = ("username", 'first_name','last_name',"gender", "birthday", "email", "phone",'area_code','address')

class UserRegSerializer(serializers.ModelSerializer):
    username = serializers.CharField(label="用户名", help_text="用户名", required=True, allow_blank=False,
                                     validators=[UniqueValidator(queryset=User.objects.all(), message="用户已经存在")])

    password = serializers.CharField(
        help_text="密码", label="密码", write_only=True,
    )

    email = serializers.EmailField(label='邮箱',help_text='邮箱',validators=[UniqueValidator(queryset=User.objects.all(), message="邮箱已注册")])

    def create(self, validated_data):
        user = super(UserRegSerializer, self).create(validated_data=validated_data)
        user.set_password(validated_data["password"])
        user.is_active = True
        user.save()
        return user

    class Meta:
        model = User
        fields = ("username", "password",'email')


class UserLoginSerializer(serializers.Serializer):
    username = serializers.CharField(label="用户名或邮箱", help_text="用户名或邮箱", required=True, allow_blank=False)
    password = serializers.CharField(help_text="密码", label="密码", write_only=True)


    def validate(self, attrs):
        credentials = {
            'username': attrs.get('username'),
            'password': attrs.get('password')
        }

        if all(credentials.values()):
            print(credentials)
            user = authenticate(**credentials)#官方验证
            print(user)
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







