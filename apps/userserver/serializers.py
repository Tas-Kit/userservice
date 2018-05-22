from rest_framework import routers, serializers
# from django.contrib.auth.models import User
from .models import Users


class UserSerializers(serializers.ModelSerializer):
    class Meta:
        model = Users
        fields = ('username','password','first_name','last_name',
                    'email','is_staff','is_active','is_superuser',
                    'birthday','gender','phone','address')


