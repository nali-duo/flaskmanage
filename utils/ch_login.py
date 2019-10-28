#验证登录的装饰器
from flask import session,redirect,url_for
from functools import wraps
def login_required(func):
    @wraps(func)
    def inner(*args,**kwargs):
        user=session.get('username')
        if user:
            return func(*args,**kwargs)
        else:
            return redirect(url_for('hello_world'))
    return inner