from django.urls import path

from . import views


urlpatterns = [
    path(r'register/', views.register_user),
    path(r'info/', views.info_user),
    path(r'login/', views.login),
    path(r'logout/', views.logout),
    path(r'add_perm/', views.add_perm),
    path(r'list_perm/', views.list_perm),
    path(r'del_perm/', views.del_perm),
]
