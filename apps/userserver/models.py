from django.db import models
from django.contrib.auth.models import User

# Create your models here.


class Users(models.Model):
    '''
    用户字段扩展
    '''
    user = models.OneToOneField(User,on_delete=models.CASCADE,primary_key=True,related_name='extra')
    # username = models.CharField(max_length=100,null=True,blank=True,unique=True)
    birthday = models.DateField(null=True,blank=True)
    # email = models.CharField(max_length=100,null=True,blank=True,unique=True)
    gender = models.CharField(max_length=6,choices=(('male','male'),('female','female')),blank=True,null=True)
    phone = models.CharField(max_length=20,blank=True,null=True,unique=True)
    address = models.TextField(blank=True,null=True)
    

    class Meta:
        verbose_name='userdata'
        verbose_name_plural = 'userdatas'

    def __str__(self):
        return str(self.user.username)