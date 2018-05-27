"""config URL Configuration

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/1.11/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  url(r'^$', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  url(r'^$', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.conf.urls import url, include
    2. Add a URL to urlpatterns:  url(r'^blog/', include('blog.urls'))
"""
from django.conf.urls import url,include
from django.contrib import admin
from rest_framework import routers, serializers, viewsets
from userserver.views import UserViewSet
from rest_framework.documentation import include_docs_urls

router = routers.DefaultRouter()
router.register(r'user', UserViewSet)

# v1 第一个版本
prefix_path = 'api/v1'

urlpatterns = [
    url(r'^%s/'%prefix_path, include(router.urls)),
    url(r'^%s/user_docs/'%prefix_path, include_docs_urls(title="用户服务管理")),
    url(r'^%s/user_admin/'%prefix_path, admin.site.urls),
    # url(r'^%s/user/api-auth/'%prefix_path, include('rest_framework.urls')),
]
