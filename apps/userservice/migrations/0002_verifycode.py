# Generated by Django 2.0.5 on 2018-06-07 04:31

import datetime
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('userservice', '0001_initial'),
    ]

    operations = [
        migrations.CreateModel(
            name='VerifyCode',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('code', models.CharField(max_length=50, verbose_name='验证码')),
                ('email', models.CharField(max_length=50, verbose_name='email')),
                ('add_time', models.DateTimeField(default=datetime.datetime.now, verbose_name='添加时间')),
            ],
            options={
                'verbose_name': '',
                'verbose_name_plural': '',
            },
        ),
    ]
