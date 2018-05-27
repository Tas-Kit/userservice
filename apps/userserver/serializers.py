from rest_framework import routers, serializers
# from django.contrib.auth.models import User
from .models import Users
from django.contrib.auth.models import User




class UsersSerializers(serializers.ModelSerializer):
    # user = UserSerializers(many=False)
    class Meta:
        model = Users
        fields = '__all__'

class UserSerializers(serializers.ModelSerializer):
    extra = UsersSerializers(many=False)
    class Meta:
        model = User
        fields = '__all__'





