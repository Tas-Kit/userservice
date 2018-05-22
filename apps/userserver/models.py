from django.db import models
from django.contrib.auth.models import AbstractUser

# Create your models here.


class Users(AbstractUser):
    '''
    用户
    '''
    username = models.CharField(max_length=100,null=True,blank=True,unique=True)
    birthday = models.DateField(null=True,blank=True)
    email = models.CharField(max_length=100,null=True,blank=True,unique=True)
    gender = models.CharField(max_length=6,choices=(('male','male'),('female','female'),('unknown','unknow'
)),default='unknow')
    phone = models.CharField(max_length=20,blank=True,null=True,unique=True)
    address = models.TextField(blank=True,null=True)
    

    class Meta:
        verbose_name='userdata'
        verbose_name_plural = 'userdatas'

    def __str__(self):
        return str(self.id)