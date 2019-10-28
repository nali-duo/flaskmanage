from flask import Blueprint,render_template,redirect,request,session
from utils.ch_login import login_required
from app import User,Grade,Student,Role,r_p,Permission
from app import db
from datetime import datetime

user_blueprint=Blueprint('user',__name__,url_prefix='/user/')
@user_blueprint.route('/head/')
@login_required
def head():
    #页头
    user=session.get('username')
    return render_template('head.html',user=user)

@user_blueprint.route('/left/')
@login_required
def left():
    # 左侧栏
    uid=request.args.get('u_id')
    if request.method=='GET':
        user=session.get('username')
        permissions=User.query.filter_by(username=user).first().role.permission
    return render_template('left.html',permissions=permissions,uid=uid)

#班级管理-班级列表
@user_blueprint.route('/grade/',methods=['GET'])
@login_required
def grade():
    if request.method=='GET':
        # grades=Grade.query.all()
        #获取当前页数,没有就默认为第1页
        page=int(request.args.get('page',1))
        #设置每页显示信息的数量
        per_page=4
        paginate=Grade.query.paginate(page,per_page,error_out=False)
        return render_template('grade.html',paginate=paginate)

#班级管理-班级添加
@user_blueprint.route('/addgrade/',methods=['GET','POST'])
@login_required
def addgrede():
    if request.method=='GET':
        return render_template('addgrade.html')
    if request.method=='POST':
        g_name=request.form.get('g_name')
        g_name1=Grade.query.filter_by(g_name=g_name).first()
        if g_name1:
            msg='班级已存在,添加失败'
            return render_template('addgrade.html',msg=msg)
        else:
            new_grade=Grade(g_name=g_name,g_create_time=datetime.now())
            db.session.add(new_grade)
            db.session.commit()
            msg='添加成功'
            return render_template('addgrade.html',msg=msg)





#班级管理-班级列表-编辑
@user_blueprint.route('/edit_grade/<g_id>',methods=['GET','POST'])
@login_required
def edit_grade(g_id):
    if request.method=='GET':
        return render_template('addgrade.html',g_id=g_id)
    if request.method=='POST':
        g_name=request.form.get('g_name')
        obj=Grade.query.filter_by(g_id=g_id).first()
        obj.g_name=g_name
        db.session.commit()
        page = int(request.args.get('page', 1))
        # 设置每页显示信息的数量
        per_page = 2
        paginate = Grade.query.paginate(page, per_page, error_out=False)
        return render_template('grade.html',paginate=paginate)

#班级管理-班级列表-删除
@user_blueprint.route('/delete/<g_id>',methods=['GET','POST'])
@login_required
def delete(g_id):
    if request.method=='GET':
        grade1=Grade.query.filter_by(g_id=g_id).first()
        db.session.delete(grade1)
        db.session.commit()
        page = int(request.args.get('page', 1))
        # 设置每页显示信息的数量
        per_page = 4
        paginate = Grade.query.paginate(page, per_page, error_out=False)
        return render_template('grade.html',paginate=paginate)



# 班级管理-班级列表-查看学生
@user_blueprint.route('/grade_student/<g_id>',methods=['GET','POST'])
@login_required
def grade_student(g_id):
    if request.method=='GET':
        page = int(request.args.get('page', 1))
        # 设置每页显示信息的数量
        per_page = 4
        #创建分液器对象,相当于已经把筛选之后所有需要的数据找出来了,并且根据设置要求进行了分页.
        paginate =Student.query.filter_by(grade_id=g_id).paginate(page, per_page, error_out=False)
        return render_template('student.html',paginate=paginate)

#学生管理-学生列表
@user_blueprint.route('/student/',methods=['GET','POST'])
@login_required
def stduent():
    if request.method=='GET':
        page=page = int(request.args.get('page', 1))
        # 设置每页显示信息的数量
        per_page = 4
        paginate=Student.query.paginate(page,per_page,error_out=False)
        return render_template('student.html',paginate=paginate)

#学生管理-学生列表-删除
@user_blueprint.route('/delstu/<s_id>',methods=['GET','POST'])
@login_required
def delstu(s_id):
    if request.method=='GET':
        delstu=Student.query.filter_by(s_id=s_id).first()
        db.session.delete(delstu)
        db.session.commit()
        # page = page = int(request.args.get('page', 1))
        # # 设置每页显示信息的数量
        # per_page = 4
        # paginate = Student.query.paginate(page, per_page, error_out=False)
        # return render_template('student.html', paginate=paginate)
        return redirect('/user/student/')


#学生管理-添加学生
@user_blueprint.route('/addstu/',methods=['GET','POST'])
@login_required
def addstu():
    if request.method=='GET':
        grades = db.session.execute('select * from Grade')
        return render_template('addstu.html',grades=grades)
    if request.method=='POST':
        s_name=request.form.get('s_name')
        s_sex=request.form.get('s_sex')
        g_id=request.form.get('g_name')
        newstu=Student(s_name=s_name,s_sex=s_sex,grade_id=g_id)
        db.session.add(newstu)
        db.session.commit()
        page = page = int(request.args.get('page', 1))
        # 设置每页显示信息的数量
        per_page = 4
        paginate = Student.query.paginate(page, per_page, error_out=False)
        return render_template('student.html',paginate=paginate)

#权限管理-角色列表
@user_blueprint.route('/roles/',methods=['GET','POST'])
@login_required
def roles():
    if request.method=='GET':
        roles = Role.query.all()
        return render_template('roles.html',roles=roles)

#权限管理-角色列表-查看权限
@user_blueprint.route('/userperlist/',methods=['GET','POST'])
@login_required
def userperlist():
    if request.method=='GET':
        r_id1 = request.args.get('r_id')
        u_role = Role.query.get(r_id1)
        permissions = u_role.permission
        return render_template('user_per_list.html',pers=permissions,r_id=r_id1)
    # 权限管理-角色列表-查看权限-删除
    if request.method=='POST':
        r_id = request.form.get('r_id')
        p_id=request.form.get('p_id')
        per=Permission.query.get(p_id)
        r_id=Role.query.get(r_id)
        r_id.permission.remove(per)
        db.session.commit()
        pers=r_id.permission
        return render_template('user_per_list.html',pers=pers,r_id=r_id)


#权限管理-角色列表-添加权限
@user_blueprint.route('/adduserper/',methods=['GET','POST'])
@login_required
def adduserper():
    r_id=request.args.get('r_id')
    if request.method=='GET':
        return render_template('addpermission.html')
    if request.method=='POST':
        p_name=request.form.get('p_name')
        p_er=request.form.get('p_er')
        p_obj=Permission.query.filter_by(p_name=p_name,p_er=p_er).first()
        sql=' insert into r_p(role_id,permission_id) values (%s, %s)' % (r_id, p_obj.p_id)
        db.session.execute(sql)
        db.session.commit()
        u_role = Role.query.filter_by(r_id=r_id).first()
        permissions = u_role.permission
        return render_template('user_per_list.html',pers=permissions)



# # 权限管理-角色列表-减少权限
# @user_blueprint.route('/subuserper/',methods=['GET','POST'])
# @login_required
# def perdelete():
#     if request.method=='GET':
#         r_id1 = request.args.get('r_id')
#         u_role = Role.query.filter_by(r_id=r_id1).first()
#         permissions = u_role.permission
#         if request.method == 'GET':
#             return render_template('user_per_list.html', pers=permissions)



#权限管理-添加角色
@user_blueprint.route('/addroles/',methods=['GET','POST'])
@login_required
def addroles():
    if request.method=='GET':
        return render_template('addroles.html')
    if request.method=='POST':
        new_role=request.form.get('r_name')
        old_role=Role.query.filter_by(r_name=new_role).first()
        if old_role:
            msg='用户已存在,添加失败'
            return render_template('addroles.html',msg=msg)
        else:
            new_role=Role(r_name=new_role)
            db.session.add(new_role)
            db.session.commit()
            msg='用户添加成功'
            return render_template('addroles.html',msg=msg)


#权限管理-权限列表
@user_blueprint.route('/permissions/',methods=['GET','POST'])
@login_required
def permissions():
    if request.method=='GET':
        permissions=Permission.query.all()
        return render_template('permissions.html',permissions=permissions)

#权限管理-添加权限
@user_blueprint.route('/addpermission/',methods=['GET','POST'])
@login_required
def addpermissions():
    if request.method=='GET':
        return render_template('addpermission.html')
    if request.method=='POST':
        p_name=request.form.get('p_name')
        p_er=request.form.get('p_er')
        new_pms=Permission(p_name=p_name,p_er=p_er)
        db.session.add(new_pms)
        db.session.commit()
        msg1='添加成功'
        return render_template('addpermission.html',msg1=msg1)

#权限管理-权限列表-编辑
@user_blueprint.route('/eidtorpermission/',methods=['GET','POST'])
@login_required
def eidtorpermission():
    pid = request.args.get('p_id')
    if request.method=='GET':
        return render_template('addpermission.html')
    if request.method=='POST':
        p_name1=request.form.get('p_name')
        p_er1=request.form.get('p_er')
        e_pms=Permission.query.filter_by(p_id=pid).first()
        e_pms.p_name=p_name1
        e_pms.p_er=p_er1
        db.session.commit()
        msg1='权限修改成功'
        return render_template('addpermission.html',msg1=msg1)

#权限管理-权限列表-删除
@user_blueprint.route('/pdelete/',methods=['GET','POST'])
@login_required
def pdelete():
    pid = request.args.get('p_id')
    if request.method=='GET':
        d_pms=Permission.query.filter_by(p_id=pid).first()
        db.session.delete(d_pms)
        db.session.commit()
        return redirect('/user/permissions/')

#用户管理-用户列表
@user_blueprint.route('/userlist/',methods=['GET','POST'])
@login_required
def userlist():
    page=int(request.args.get('page',1))
    per_page=4
    paginate=User.query.paginate(page,per_page,error_out=False)
    if request.method=='GET':
        return render_template('users.html',paginate=paginate)

# 用户管理-用户列表-分配角色
@user_blueprint.route('/assignrole/',methods=['GET','POST'])
@login_required
def assignrole():
    if request.method == 'GET':
        roles=Role.query.all()
        return render_template('assign_user_role.html',roles=roles)
    if request.method == 'POST':
        u_id=request.args.get('u_id')
        old=User.query.filter_by(u_id=u_id).first()
        r_id=request.form.get('r_id')
        old.role_id=r_id
        db.session.commit()
        return redirect('/user/userlist/')

# 用户管理-用户列表-删除
@user_blueprint.route('/udelete/',methods=['GET','POST'])
@login_required
def udelet():
    if request.method=='GET':
        u_id=request.args.get('u_id')
        del_u=User.query.filter_by(u_id=u_id).first()
        db.session.delete(del_u)
        db.session.commit()
        return redirect('/user/userlist/')

#用户管理-添加用户
@user_blueprint.route('/adduser/',methods=['GET','POST'])
@login_required
def adduser():
    if request.method == 'GET':
        return render_template('adduser.html')
    if request.method=='POST':
        username=request.form.get('username')
        password1=request.form.get('password1')
        password2=request.form.get('password2')
        if password1==password2:
            msg='添加用户成功'
            new_user=User(username=username,password=password1,u_create_time=datetime.now())
            db.session.add(new_user)
            db.session.commit()
            return render_template('adduser.html',msg=msg)
        else:
            msg='用户添加失败'
            return render_template('adduser.html', msg=msg)


#系统管理-修改密码
@user_blueprint.route('/changepwd/<uid>',methods=['GET','POST'])
@login_required
def changepwd(uid):
    user = User.query.filter_by(u_id=uid).first()
    if request.method == 'GET':
        return render_template('changepwd.html',user=user)
    if request.method=='POST':
        old_pass=request.form.get('pwd1')
        if old_pass==user.password:
            msg='密码修改成功'
            new_pass=request.form.get('pwd2')
            rnew_pass=request.form.get('pwd3')
            if new_pass==rnew_pass and len(new_pass)!=0:
                user.password=new_pass
                db.session.commit()
                return render_template('changepwd.html',user=user,msg=msg)
            else:
                msg1='旧密码正确,新密码两次输入的不一致'
                return render_template('changepwd.html',user=user,msg=msg1)
        else:
            msg='旧密码输入错误'
            return render_template('changepwd.html',user=user,msg=msg)



#注册界面
@user_blueprint.route('/register',methods=['GET'])
@login_required
def register():
    if request.method=='GET':
        return render_template('register.html')

# 退出登录
@user_blueprint.route('/logout/',methods=['GET'])
@login_required
def logout():
    if request.method=='GET':
        session.clear()
        return redirect('/')