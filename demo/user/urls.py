from django.urls import path

from . import views


urlpatterns = [
    # 用户信息
    path(r'register/', views.register_user),
    path(r'read_user/', views.read_user),
    path(r'edit_user/', views.edit_user),
    path(r'del_user/', views.del_user),
    path(r'list_user/', views.list_user),

    # 系统登录、登出
    path(r'login/', views.login),
    path(r'logout/', views.logout),

    # 用户权限
    path(r'add_perm/', views.add_perm),
    path(r'list_perm/', views.list_perm),
    path(r'del_perm/', views.del_perm),
]
