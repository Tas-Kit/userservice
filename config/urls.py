"""config URL Configuration

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/2.0/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from django.urls import path, include
from rest_framework.documentation import include_docs_urls
from userservice.views import (
    UserSignUp,
    UserLogin,
    UserInfo,
    UsersViewSet,
    ResetPassword,
    SetPassword,
    UploadProfile,
    UploadImage
)
from rest_framework import routers
from rest_framework_jwt.views import obtain_jwt_token, refresh_jwt_token
from django.http import HttpResponse
router = routers.DefaultRouter()
router.register(r'', UsersViewSet, base_name='users')

api_v1_userservice_url = [
    # path('api/v1/', include(router.urls)),
    path('exempt/signup/', UserSignUp.as_view()),
    path('exempt/login/', UserLogin.as_view()),
    path('exempt/reset_password/', ResetPassword.as_view()),
    path('exempt/set_password/', SetPassword.as_view()),
    path('userinfo/', UserInfo.as_view()),
    path('upload_image/', UploadImage.as_view()),
    path('upload_profile/', UploadProfile.as_view()),
    path('users/', include(router.urls)),
    path('exempt/get_jwt/', obtain_jwt_token),
    path('refresh_jwt/', refresh_jwt_token),
    path('user_docs/', include_docs_urls(title="user")),
]

urlpatterns = [
    path('healthcheck/', lambda request:HttpResponse('HEALTHY')),
    path('api/v1/userservice/', include(api_v1_userservice_url))
]
