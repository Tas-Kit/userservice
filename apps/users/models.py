from django.db import models
import uuid
# Create your models here.
from django.contrib.auth.models import AbstractUser

# Create your models here.


class Users(AbstractUser):
    '''
    用户
    '''
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    birthday = models.DateField(null=True,blank=True)
    gender = models.CharField(max_length=6,choices=(('male','male'),('female','female'),('unknown','unknow'
)),default='unknow')
    area_code = models.CharField(max_length=10,blank=True,null=True)
    phone = models.CharField(max_length=20,blank=True,null=True)
    address = models.TextField(blank=True,null=True)


    class Meta:
        verbose_name = "用户"
        verbose_name_plural = verbose_name

    def __str__(self):
        return self.username

    # def save(self,**kwsg):
    #     super().save()


    

