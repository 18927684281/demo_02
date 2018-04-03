from django.urls import path

from . import views


urlpatterns = [
    # 用户信息
    path(r'add_user/', views.add_user),
    path(r'read_user/', views.read_user),
    path(r'edit_user/', views.edit_user),
    path(r'del_user/', views.del_user),
    path(r'list_user/', views.list_user),

    # 系统登录、登出
    path(r'login/', views.login),
    path(r'logout/', views.logout),

    # 用户的权限
    path(r'add_user_perm/', views.add_user_perm),
    path(r'list_user_perm/', views.list_user_perm),
    path(r'del_user_perm/', views.del_user_perm),

    # 权限
]
