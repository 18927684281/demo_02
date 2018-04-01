from django.shortcuts import render, redirect

from .models import User


def check_perm(perm_name):
    def wrap1(view_func):
        def wrap2(request, *args, **kwargs):
            uid = request.session.get('uid')
            if uid is None:
                # 未登录
                url = '/user/login/'
                request = redirect(url)
            else:
                pass
                user = User.objects.get(pk=uid)
                if user.has_perm(perm_name):
                    # 成功
                    request = view_func(request, *args, **kwargs)
                else:
                    # 失败
                    tpl_name = 'user/permission_denied.html'
                    request = render(request, tpl_name)
            return request
        return wrap2
    return wrap1
