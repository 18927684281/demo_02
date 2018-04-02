from django.shortcuts import render, redirect
# from django.core.exceptions import ObjectDoesNotExist

from .models import Permission, Role, User
from .helper import check_perm


def register_user(request):
    ''' 用户注册 '''
    if request.method == 'POST':
        # 保存注册数据
        nickname = request.POST.get('nickname')
        if User.objects.filter(nickname__exact=nickname).exists():
            # "昵称"存在
            info = {'error': '"昵称"存在'}
            # 显示注册页面
            tpl_name = 'user/register.html'
            return render(request, tpl_name, info)

        password = request.POST.get('password')
        password2 = request.POST.get('password2')
        if password != password2:
            # 2次密码不一致
            info = {'error': '2次密码不一致'}
            # 显示注册页面
            tpl_name = 'user/register.html'
            return render(request, tpl_name, info)

        age = request.POST.get('age')
        sex = request.POST.get('sex')
        f_in = request.FILES.get('icon')
        user = User(nickname=nickname, password=password, age=age, sex=sex)
        if f_in:
            user.icon.save(f_in.name, f_in, save=False)
        user.set_password(password)
        user.save()

        # 在session中，记录用户信息
        request.session['uid'] = user.id
        request.session['nickname'] = user.nickname

        # 跳转到用户信息
        url = '/user/info/?uid={}'.format(user.id)
        return redirect(url)
    else:
        # 显示注册页面
        tpl_name = 'user/register.html'
        info = {'error': 'test'}
        return render(request, tpl_name, info)


# @check_perm('admin')
def info_user(request):
    ''' 显示用户信息 '''
    uid = request.session['uid']
    user = User.objects.get(pk=uid)
    info = {'user': user}
    tpl_name = 'user/info.html'
    return render(request, tpl_name, info)


def login(request):
    ''' 登录 '''
    info = {}
    if request.method == 'POST':
        nickname = request.POST.get('nickname')
        password = request.POST.get('password')
        print('nickname: {}, password: {}'.format(nickname, password))
        user = User.objects.filter(nickname__exact=nickname).first()
        if user is None:
            # "昵称"不存在
            info = {'error': '"昵称"不存在'}
        elif not user.check_password(password):
            # 密码错误
            info = {'error': '密码错误', 'nickname': nickname}
        else:
            request.session['uid'] = user.id
            request.session['nickname'] = user.nickname
            url = '/user/info/?uid={}'.format(user.id)
            return redirect(url)
    tpl_name = 'user/login.html'
    return render(request, tpl_name, info)


def logout(request):
    ''' 登出 '''
    request.session.flush()
    tpl_name = 'user/login.html'
    return render(request, tpl_name)


@check_perm('admin')
def add_perm(request):
    ''' 增加权限 '''
    info = {}
    if request.method == 'POST':
        # 用户提交
        try:
            uid = int(request.POST.get('uid', 0))
            perm_id = int(request.POST.get('perm_id', 0))
            user = User.objects.get(pk=uid)
            perm = Permission.objects.get(pk=perm_id)
            user.add_perm(perm.name)
            url = '/user/list_perm/?uid={}'.format(uid)
            return redirect(url)
        except Exception as e:
            info['error'] = str(e)
    # 显示"增加权限"的界面
    tpl_name = 'user/add_perm.html'
    if 'users' not in info:
        info['users'] = User.objects.all()
    if 'perms' not in info:
        info['perms'] = Permission.objects.all()
    pass
    return render(request, tpl_name, info)


def list_perm(request):
    ''' 显示指定用户的权限 '''
    info = {
            'user': None,
            'perms': None,
            }
    tpl_name = 'user/list_perm.html'
    uid = int(request.GET.get('uid', 0))
    user = User.objects.filter(pk=uid).first()
    if user:
        info['user'] = user
        arr_id_perm = tuple(
                Role.objects.filter(uid=user.id).values_list(flat=True)
                )
        perms = Permission.objects.filter(id__in=arr_id_perm).all()
        info['perms'] = perms
    else:
        info['error'] = '用户(id={})不存在'.format(uid)
    return render(request, tpl_name, info)
