from flask import Flask,request,render_template,redirect,session,jsonify
from config import Config
from datetime import datetime
#导入orm操作的类
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import *
from flask_migrate import Migrate

app = Flask(__name__)
app.config.from_object(Config)
db=SQLAlchemy(app)
migrate=Migrate(app,db)



#班级模型
class Grade(db.Model):
    __tablename__='grade'
    g_id=db.Column(db.Integer,autoincrement=True,primary_key=True)
    g_name=db.Column(db.String(20),unique=True)
    g_create_time=db.Column(db.DateTime,default=datetime.now)
    student=db.relationship('Student',backref='grade')

#学生模型类
class Student(db.Model):
    __tablename__='student'
    s_id=db.Column(db.Integer,autoincrement=True,primary_key=True)
    s_name=db.Column(db.String(16),unique=True)
    s_sex=db.Column(db.Integer)
    grade_id=db.Column(db.Integer,db.ForeignKey('grade.g_id'),nullable=True)

#用户模型类
class User(db.Model):
    __tablename__='user'
    u_id=db.Column(db.Integer,autoincrement=True,primary_key=True)
    username=db.Column(db.String(16),unique=True)
    password=db.Column(db.String(250))
    u_create_time=db.Column(db.DateTime,default=datetime.now)
    role_id=db.Column(db.Integer,db.ForeignKey('role.r_id'))

#角色模型
class Role(db.Model):
    __tablename__='role'
    r_id=db.Column(db.Integer,autoincrement=True,primary_key=True)
    r_name=db.Column(db.String(10))
    user=db.relationship('User',backref='role')

#角色和权限的(多对多的)关联表
#r_p为关联表的表名
r_p=db.Table('r_p',
             db.Column('role_id',db.Integer,db.ForeignKey('role.r_id'),primary_key=True),
             db.Column('permission_id',db.Integer,db.ForeignKey('permission.p_id'),primary_key=True))

#权限模型表
class Permission(db.Model):
    __tablename__='permission'
    p_id=db.Column(db.Integer,autoincrement=True,primary_key=True)
    p_name=db.Column(db.String(16),unique=True)
    p_er=db.Column(db.String(16),unique=True)
    roles=db.relationship('Role',secondary=r_p,backref=db.backref('permission',lazy=True))

@app.route('/',methods=['GET','POST'])
def hello_world():
    if request.method=='GET':
        return render_template('login.html')
    if request.method=='POST':
        username=request.form.get('username')
        password=request.form.get('password')
        user=User.query.filter_by(username=username,password=password).first()
        if user:
            session['username']=username
            session['password']=password
            return render_template('index.html',u_id=user.u_id)
        else:
            msg='登录失败'
            return render_template('login.html',msg=msg)




from view.user_blueprint import user_blueprint
app.register_blueprint(user_blueprint)

if __name__ == '__main__':
    app.run()

