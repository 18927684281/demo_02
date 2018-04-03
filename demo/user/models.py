from django.db import models
from django.contrib.auth.hashers import make_password, check_password
from django.core.exceptions import ObjectDoesNotExist


class User(models.Model):
    ''' 用户信息 '''
    nickname = models.CharField(
            max_length=128, null=False, blank=False, unique=True,
            )
    password = models.CharField(max_length=128)
    icon = models.ImageField()
    age = models.IntegerField()
    sex = models.IntegerField()

    def __str__(self):
        return self.nickname

    def set_password(self, password):
        ''' 设置密码 '''
        self.password = make_password(password)

    def check_password(self, password):
        return check_password(password, self.password)

    def add_perm(self, perm_name):
        ''' 增加权限 '''
        try:
            perm = Permission.objects.get(name=perm_name)
        except User.DoesNotExist as e:
            return e
        UserPermission.objects.get_or_create(uid=self.id, perm_id=perm.id)

    def del_perm(self, perm_name):
        ''' 删除权限 '''
        try:
            perm = Permission.objects.get(name=perm_name)
            UserPermission.objects.get(uid=self.id, perm_id=perm.id).delete()
        except ObjectDoesNotExist as e:
            print(e)

    def has_perm(self, perm_name):
        ''' 检查权限 '''
        perm = Permission.objects.get(name=perm_name)
        flag = UserPermission.objects.filter(uid=self.id, perm_id=perm.id)
        return flag


class Permission(models.Model):
    ''' 权限 '''
    name = models.CharField(
            max_length=64, null=False, blank=False, unique=True,
            )

    def __str__(self):
        return self.name


class UserPermission(models.Model):
    ''' 用户--权限 关联表 '''
    uid = models.IntegerField()
    perm_id = models.IntegerField()

    def __str__(self):
        user = User.objects.get(pk=self.uid)
        perm = Permission.objects.get(pk=self.perm_id)
        return '{}-{}'.format(user.nickname, perm.name)
