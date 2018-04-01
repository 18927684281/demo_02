from django.shortcuts import render, redirect
from django.core.exceptions import ObjectDoesNotExist

from .models import User


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

