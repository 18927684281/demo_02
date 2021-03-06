import json

from django.shortcuts import render, redirect
from django.core.exceptions import ObjectDoesNotExist

from .models import Permission, User, UserPermission
from .helper import check_perm


def add_user(request):
    ''' 用户注册 '''
    info = {}
    tpl_name = 'user/add_user.html'
    if request.method == 'POST':
        # 保存注册数据
        nickname = request.POST.get('nickname')
        if User.objects.filter(nickname__exact=nickname).exists():
            # "昵称"存在
            info = {'error': '"昵称"存在'}
            # 显示注册页面
            return render(request, tpl_name, info)

        password = request.POST.get('password')
        password2 = request.POST.get('password2')
        if password != password2:
            # 2次密码不一致
            info = {'error': '2次密码不一致'}
            # 显示注册页面
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
        url = '/user/read_user/?uid={}'.format(user.id)
        return redirect(url)
    else:
        # 显示注册页面
        return render(request, tpl_name, info)


# @check_perm('admin')
def read_user(request):
    ''' 显示用户信息 '''
    info = {'user': None}
    uid = int(request.GET.get('uid', 0))
    try:
        user = User.objects.get(pk=uid)
        info['user'] = user
    except Exception:
        info['error'] = '用户不存在'
    tpl_name = 'user/read_user.html'
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
            url = '/user/read_user/?uid={}'.format(user.id)
            return redirect(url)
    tpl_name = 'user/login.html'
    return render(request, tpl_name, info)


def logout(request):
    ''' 登出 '''
    request.session.flush()
    tpl_name = 'user/login.html'
    return render(request, tpl_name)


@check_perm('admin')
def add_user_perm(request):
    ''' 增加权限 '''
    info = {
            'user': None,
            'perms': None,
            'all_perms': None,
            }
    arr_error = []
    if request.method == 'POST':
        # 用户提交
        try:
            uid = int(request.POST.get('uid', 0))
            s_id_perm = request.POST.getlist('perm_id')
            arr_id_perm = [int(s) for s in s_id_perm]
            for perm_id in arr_id_perm:
                UserPermission.objects.get_or_create(uid=uid, perm_id=perm_id)
            return redirect('/user/list_user_perm/?uid={}'.format(uid))
        except ObjectDoesNotExist:
            arr_error.append('记录不存在')
        except Exception as e:
            arr_error.append(str(e))
    # 显示"增加权限"的界面
    try:
        uid = int(request.GET.get('uid', 0))
        user = User.objects.get(pk=uid)
        arr_perm_id = UserPermission.objects.filter(uid=uid).values_list(
                'perm_id', flat=True,
                )
        perms = Permission.objects.filter(id__in=arr_perm_id).all()
        if info['user'] is None:
            info['user'] = user
        if info['perms'] is None:
            info['perms'] = perms
        if info['all_perms'] is None:
            info['all_perms'] = Permission.objects.all()
    except ObjectDoesNotExist:
        arr_error.append('记录不存在')
    except Exception as e:
        arr_error.append(str(e))
    if arr_error:
        info['error'] = json.dumps(arr_error, ensure_ascii=False)
    tpl_name = 'user/add_user_perm.html'
    print('info: {}'.format(info))
    return render(request, tpl_name, info)


def list_user_perm(request):
    ''' 显示指定用户的权限 '''
    info = {
            'user': None,
            'perms': None,
            }
    tpl_name = 'user/list_user_perm.html'
    uid = int(request.GET.get('uid', 0))
    user = User.objects.filter(pk=uid).first()
    if user:
        info['user'] = user
        arr_id_perm = tuple(
                UserPermission.objects.filter(uid=uid).values_list(
                    'perm_id', flat=True
                    )
                )
        perms = Permission.objects.filter(id__in=arr_id_perm).all()
        info['perms'] = perms
    else:
        info['error'] = '用户(id={})不存在'.format(uid)
    return render(request, tpl_name, info)


def del_user_perm(request):
    ''' 删除权限 '''
    info = {}
    arr_error = []
    uid = None
    try:
        if request.method == 'POST':
            # 用户提交
            uid = int(request.POST.get('uid', 0))
            s_id_perm = request.POST.getlist('perm_id')
            arr_id_perm = [int(s) for s in s_id_perm]
            UserPermission.objects.filter(
                    uid=uid, perm_id__in=arr_id_perm
                    ).delete()
            return redirect('/user/list_user_perm/?uid={}'.format(uid))
    except Exception as e:
        arr_error.append(str(e))
    try:
        if uid is None:
            uid = int(request.GET.get('uid', 0))
        user = User.objects.get(pk=uid)
        arr_id_perm = UserPermission.objects.filter(uid=uid).values_list(
                'perm_id', flat=True,
                )
        perms = Permission.objects.filter(id__in=arr_id_perm).all()
        if 'user' not in info:
            info['user'] = user
        if 'perms' not in info:
            info['perms'] = perms
        if 'all_perms' not in info:
            info['all_perms'] = Permission.objects.all()
    except Exception as e:
        arr_error.append(str(e))
    if arr_error:
        info['error'] = json.dumps(arr_error)
    tpl_name = 'user/del_user_perm.html'
    return render(request, tpl_name, info)


def edit_user(request):
    ''' 修改用户信息 '''
    info = {'user': None}
    arr_error = []
    if request.method == 'POST':
        try:
            # 用户提交
            uid = int(request.POST.get('uid', 0))
            f_in = request.FILES.get('icon')
            age = int(request.POST.get('age', 0))
            sex = int(request.POST.get('sex', 0))
            user = User.objects.get(pk=uid)
            user.age = age
            user.sex = sex
            if f_in:
                user.icon.save(f_in.name, f_in, save=False)
            user.save()
            # 跳转到用户信息
            url = '/user/read_user/?uid={}'.format(user.id)
            return redirect(url)
        except Exception as e:
            arr_error.append(str(e))
    # 显示"修改用户信息"的界面
    if info['user'] is None:
        try:
            uid = int(request.GET.get('uid', 0))
            user = User.objects.get(pk=uid)
            info['user'] = user
        except ObjectDoesNotExist:
            arr_error.append('记录不存在')
        except Exception as e:
            arr_error.append(str(e))
    if arr_error:
        info['error'] = json.dumps(arr_error, ensure_ascii=False)
    tpl_name = 'user/edit_user.html'
    return render(request, tpl_name, info)


def list_user(request):
    ''' 显示用户列表 '''
    tpl_name = 'user/list_user.html'
    users = User.objects.all()
    info = {'users': users}
    return render(request, tpl_name, info)


def del_user(request):
    ''' 用户删除 '''
    info = {}
    arr_error = []
    try:
        if request.method == 'POST':
            # 用户提交
            uid = int(request.POST.get('uid', 0))
            User.objects.get(pk=uid).delete()
            return redirect('/user/list_user/')
    except Exception as e:
        arr_error.append(str(e))
    users = User.objects.all()
    if 'users' not in info:
        info['users'] = users
    if arr_error:
        info['error'] = json.dumps(arr_error)
    tpl_name = 'user/del_user.html'
    return render(request, tpl_name, info)


def add_permission(request):
    ''' 权限名称的增加 '''
    info = {}
    tpl_name = 'user/add_permission.html'
    if request.method == 'POST':
        # 保存提交数据
        name = request.POST.get('name')
        if Permission.objects.filter(name__exact=name).exists():
            # 名称存在
            info = {'error': '"名称"存在'}
            return render(request, tpl_name, info)
        perm = Permission.objects.create(name=name)
        # 跳转到权限信息
        url = '/user/read_permission/?perm_id={}'.format(perm.id)
        return redirect(url)
    else:
        # 显示权限名称页面
        return render(request, tpl_name, info)


def read_permission(request):
    ''' 显示权限名称信息 '''
    info = {}
    tpl_name = 'user/read_permission.html'
    perm_id = int(request.GET.get('perm_id', 0))
    try:
        perm = Permission.objects.get(pk=perm_id)
        info['perm'] = perm
    except Exception:
        info['error'] = '权限名称不存在'
    return render(request, tpl_name, info)


def edit_permission(request):
    ''' 修改权限名称信息 '''
    info = {'perm': None}
    arr_error = []
    tpl_name = 'user/edit_permission.html'
    if request.method == 'POST':
        try:
            # 用户提交
            name = request.POST.get('name')
            print('name: {}'.format(name))
            if Permission.objects.filter(name=name).exists():
                # "权限名称"存在
                info = {'error': '"名称"存在'}
                return render(request, tpl_name, info)
            perm_id = int(request.POST.get('perm_id', 0))
            print('perm_id: {}'.format(perm_id))
            perm = Permission.objects.get(pk=perm_id)
            perm.name = name
            perm.save()
            # 跳转到权限名称信息
            url = '/user/read_permission/?perm_id={}'.format(perm.id)
            return redirect(url)
        except Exception as e:
            arr_error.append(str(e))
    # 显示"修改权限名称信息"的界面
    if info['perm'] is None:
        try:
            perm_id = int(request.GET.get('perm_id', 0))
            perm = Permission.objects.get(pk=perm_id)
            info['perm'] = perm
        except ObjectDoesNotExist:
            arr_error.append('记录不存在')
        except Exception as e:
            arr_error.append(str(e))
    if arr_error:
        info['error'] = json.dumps(arr_error, ensure_ascii=False)
    return render(request, tpl_name, info)


def list_permission(request):
    ''' 显示权限名称的列表 '''
    tpl_name = 'user/list_permission.html'
    perms = Permission.objects.all()
    info = {'perms': perms}
    return render(request, tpl_name, info)


def del_permission(request):
    ''' 删除权限名称 '''
    info = {}
    arr_error = []
    perm_id = None
    if request.method == 'POST':
        try:
            # 用户提交
            perm_id = int(request.POST.get('perm_id', 0))
            Permission.objects.filter(pk=perm_id).delete()
            return redirect('/user/list_permission/')
        except Exception as e:
            arr_error.append(str(e))
    try:
        perms = Permission.objects.all()
        if 'perms' not in info:
            info['perms'] = perms
    except Exception as e:
        arr_error.append(str(e))
    tpl_name = 'user/del_permission.html'
    return render(request, tpl_name, info)
