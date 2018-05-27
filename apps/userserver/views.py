from django.shortcuts import render
from rest_framework import mixins
from rest_framework import viewsets
from .serializers import UserSerializers
from .models import Users,User
from rest_framework.authentication import SessionAuthentication
from rest_framework.permissions import AllowAny
from rest_framework import filters
from rest_framework.pagination import PageNumberPagination
from django_filters.rest_framework import DjangoFilterBackend


# Create your views here.

class UserPage(PageNumberPagination):
    page_size = 2
    page_size_query_param = 'page_size'
    page_query_param = "page"
    max_page_size = 20

class UserViewSet(
                  mixins.CreateModelMixin,
                  mixins.UpdateModelMixin,
                  mixins.ListModelMixin,
                  mixins.DestroyModelMixin,
                  mixins.RetrieveModelMixin,
                  viewsets.GenericViewSet):

    serializer_class = UserSerializers
    queryset = User.objects.all()
    # authentication_classes = ()
    pagination_class = UserPage

    filter_backends = (DjangoFilterBackend,filters.SearchFilter)
    
    filter_fields = ('username','first_name','last_name','is_active', 'is_staff','is_superuser','email')
    search_fields = ('username','first_name','last_name','email')

