from django.db import models
from django.contrib.auth.hashers import make_password, check_password


class User(models.Model):
    nickname = models.CharField(
            max_length=128, null=False, blank=False, unique=True,
            )
    password = models.CharField(max_length=128)
    icon = models.ImageField()
    age = models.IntegerField()
    sex = models.IntegerField()

    def set_password(self, password):
        ''' 设置密码 '''
        self.password = make_password(password)

    def check_password(self, password):
        return check_password(password, self.password)
