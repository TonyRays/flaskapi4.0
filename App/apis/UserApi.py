# coding=utf-8
import uuid

from flask import abort, request, g
from flask_restful import Resource, reqparse, fields, marshal, marshal_with
from werkzeug.security import generate_password_hash, check_password_hash
from App.ext import cache
from App.models.UserModel import *
#from flask_login import login_user

# 输出参数
parser = reqparse.RequestParser()
#parser_user = reqparse.RequestParser()

#parser.add_argument('user', required=True, help="请输入操作者身份mentors/students")
# 比较常见的位置直接放在   ?action=login, register
#parser.add_argument('action', required=True, help="请提供具体操作")


# ————————————————————   Labs 注册 ———————————————————————————————— #
# 内层参数格式化
labs_fields = {
    'lab_id' : fields.Integer,
    'lab_name': fields.String,
    'lab_info': fields.String,
    'lab_time': fields.DateTime
    # lab_permission': fields.Integer,
}

# 外层输出参数格式化
response_labs_fields = {
    'status': fields.Integer,
    'msg': fields.String,
    'data': fields.Nested(labs_fields)
}


# /labs/register/
class LabsRegister(Resource):

    def post(self):
        parser = reqparse.RequestParser()
        parser.add_argument('l_name', required=True, help="请输入lab名称")
        parser.add_argument('l_info', required=True, help="请输入lab信息")
        #global user

        args = parser.parse_args()

        #users = args.get("user")
        #action = args.get("action")
        l_name = args.get("l_name")
        l_info = args.get("l_info")

        #global data
        data = {
            "status": 201,
            "msg": 'lab register ok, please register mentors then!'
        }

        user = Labs()
        
        # 防止重复注册
        if user.query.filter(Labs.lab_name.__eq__(l_name)).one_or_none():
            data['status'] = 403
            data['msg'] = 'lab has already registered'
            return data

        else:

            user.lab_name = l_name
            user.lab_info = l_info
            user.lab_time = datetime.now()

            user.save()

            data['data'] = user
            return marshal(data, response_labs_fields)

    # eg. curl http://localhost:5000/mentors/register/
    def get(self):
        return marshal(data, response_labs_fields)


# /labs/modify/<int:id>/
class Labsmodify(Resource):
    # 根据 id 获取
    @authm.login_required
    @marshal_with(response_labs_fields)
    def get(self, id):
        user = Labs.query.get(id)

        data = {
            "status": 200,
            "msg": 'ok',
            'data': user,
        }
        return data

    # 根据 id 修改
    @authm.login_required
    @marshal_with(response_labs_fields)
    def post(self, id):
        parser = reqparse.RequestParser()
        parser.add_argument('l_name', required=True, help="请输入lab名称")
        parser.add_argument('l_info', required=True, help="请输入lab信息")
        args = parser.parse_args()
        l_name = args.get("l_name")
        l_info = args.get("l_info")

        user = Labs.query.get(id)  # 根据id获得labs

        if not user:
            abort(401, message="user not login or didnt find id")

        else:
            user.lab_name = l_name
            user.lab_info = l_info
            #user.lab_time = datetime.now()

            user.save()

            data = {
            "status": 200,
            "msg": 'labs change ok',
            'data': user
            }
            return data        







'''
# /labs/<int:mentor_id>/<int:lab_id>/operation1
class operation1(Resource):
    # 操作labs operation1
    @authm.login_required
    @marshal_with(response_mentors_fields)
    def POST(self, mentor_id):
        user = Mentors.query.get(mentor_id)
        if user.lab_id
        #data = {
        #    "status": 200,
        #    "msg": 'ok',
        #    'data': user,
        #}
        #return data
        return 

    # 根据 id 修改用户信息 --> 密码修改
    @authm.login_required
    @marshal_with(response_mentors_fields)
    def post(self, mentor_id):
        parser = reqparse.RequestParser()
        parser.add_argument('u_password', required=True, help="请输入修改后的密码")
        args = parser.parse_args()

        u_password = args.get("u_password")

        user = Mentors.query.get(id)  # 根据id获得用户

        user.mentor_password = user.men_password(u_password)

        user.save()

        data = {
            "status": 200,
            "msg": 'password change ok',
            'data': user
        }
        return data

    # 根据 id 删除某个用户   Model中应该设计一个字段 is_delete 来判断是否已删除
    @authm.login_required
    @marshal_with(response_mentors_fields)
    def delete(self, id):
        user = Mentors.query.get(id)

        user.is_delete = True  # is_delete = 1  表示删除用户

        user.save()

        data = {
            "status": 200,
            "msg": 'delete ok',
            "data": user
        }
        return data

'''



# ————————————————————   Mentors 注册和登录———————————————————————————————— #

mentors_fields = {
    'mentor_id': fields.Integer,
    'mentor_name': fields.String,
    'lab_id': fields.Integer
    #'mentor_permission': fields.Integer,
}

# 外层输出参数格式化
response_mentors_fields = {
    'status': fields.Integer,
    'msg': fields.String,
    'data': fields.Nested(mentors_fields)
}


# 外层输出参数格式化  + token
response_mentors_token_fields = {
    'status': fields.Integer,
    'msg': fields.String,
    'token': fields.String,
    'data': fields.Nested(mentors_fields)
}


# /mentors/register/
class MentorsRegister(Resource):

    def post(self):
        #global user
        parser = reqparse.RequestParser()
        parser.add_argument('u_name', required=True, help="请输入用户名")
        parser.add_argument('u_password', required=True, help="请输入密码")
        parser.add_argument('l_id', required=True, help="请输入lab_id")
        args = parser.parse_args()

        #users = args.get("user")
        #action = args.get("action")
        u_name = args.get("u_name")
        u_password = args.get("u_password")
        l_id = args.get("l_id")

        #global data
        data = {
            "status": 201,
            "msg": 'mentor register ok'
        }

        user = Mentors()

        # 如果重复注册
        if user.query.filter(Mentors.mentor_name.__eq__(u_name)).one_or_none():
            data['status'] = 403
            data['msg'] = 'mentor has already registered'
            return data

        else:
            # register_mentors(user, u_name, u_password)
            user.mentor_name = u_name

            # 最终方法  密码做数据安全处理

            user.mentor_password = user.men_password(u_password)
            user.lab_id = l_id

            user.save()

            data['data'] = user

            return marshal(data, response_mentors_token_fields)

    # eg. curl http://localhost:5000/mentors/register/
    def get(self):
        return marshal(data, response_mentors_token_fields)


# /mentors/login/
class MentorsLogin(Resource):

    def post(self):
        parser = reqparse.RequestParser()
        parser.add_argument('u_name', required=True, help="请输入用户名")
        parser.add_argument('u_password', required=True, help="请输入密码")

        global user

        args = parser.parse_args()

        #users = args.get("user")
        #action = args.get("action")
        u_name = args.get("u_name")
        u_password = args.get("u_password")

        global data
        data = {
            "status": 201,
            "msg": 'mentor login ok'
        }

        #token = request.args.get("token")
        #if token:
            #abort(401, message="User has already login.")
        #else:
        user = Mentors.query.filter(Mentors.mentor_name.__eq__(u_name)).one_or_none()

        #login_mentors(user, u_password)

        if user:   # 如果用户存在
            
            # 如果用户已经登录
            if user.is_login:
                data['status'] = 403
                data['msg'] = 'mentor is login'
                return data
            

            # 如果密码错误
            if not user.verify_password(u_password):
                data['status'] = 406
                data['msg'] = 'password fail'
                return data

            # 如果用户已被删除
            elif user.is_delete:
                data['status'] = 900
                data['msg'] = 'mentor is deleted'
                return data

            else:
                g.user = user  # 赋给全局

                data['data'] = user

                # 生成token
                token = user.generate_auth_token(600)

                # token = str(uuid.uuid4())  # token 需要转换为字符串

                # 将用户token 存到缓存中 可以根据token 找到用户id 也可以根据用户id 找到token
                # key: 使用token  值:用户id
                # 第一个参数是键，这个主要是用来获取这个缓存的值。第二个参数是值。第三个参数是秒
                cache.set(token, user.mentor_id, timeout=60*60*24*7)
                if not cache.get(token):
                   abort(403, message="fail to set token")

                data['token'] = token
                user.is_login = True
                user.save()
                return marshal(data, response_mentors_token_fields)

        else:
            data['status'] = 406
            data['msg'] = 'mentor not exist'
            #return data

        data['data'] = user
        return marshal(data, response_mentors_token_fields)

    #eg. curl http://localhost:5000/mentors/register/
    def get(self):
        return marshal(data, response_mentors_token_fields)


# /mentors/<int:id>/
class MentorUser(Resource):
    # 根据 id 获取用户信息
    @authm.login_required
    @marshal_with(response_mentors_fields)
    def get(self, id):
        user = Mentors.query.get(id)

        data = {
            "status": 200,
            "msg": 'ok',
            'data': user,
        }
        return data

    # 根据 id 修改用户信息 --> 密码修改
    @authm.login_required
    @marshal_with(response_mentors_fields)
    def post(self, id):
        parser = reqparse.RequestParser()
        #parser.add_argument('u_password', required=True, help="请输入原密码")
        #parser.add_argument('u_new_password', required=True, help="请输入修改后的密码")
        parser.add_argument('u_password', required=True, help="请输入密码")
        args = parser.parse_args()

        u_password = args.get("u_password")
        #u_new_password = args.get("u_new_password")

        user = Mentors.query.get(id)  # 根据id获得用户

        #if user.mentor_password is not u_password:
        #    abort(401, message="user not login")

        user.mentor_password = user.men_password(u_password)

        user.save()

        data = {
            "status": 200,
            "msg": 'password change ok',
            'data': user
        }
        return data

    # 根据 id 删除某个用户   Model中应该设计一个字段 is_delete 来判断是否已删除
    @authm.login_required
    @marshal_with(response_mentors_fields)
    def delete(self, id):
        user = Mentors.query.get(id)

        user.is_delete = True  # is_delete = 1  表示删除用户

        user.save()

        data = {
            "status": 200,
            "msg": 'delete ok',
            "data": user
        }
        return data

'''
# /mentors/<int:id>/givepermission/<int:lab_id>/<int:s_id>/
#验证：
#检查Mentors已登录，检查拥有lab的权限，给予学生权限
class Mentorsgivepermission(Resource):
    @authm.login_required
    def get(self, id):
        data = {
            "status": 201,
            "msg": 'ok'
        }

        user = Mentors.query.get(id)

        # 如果id不存在
        if not Mentors.query.filter(Mentors.mentor_id.__eq__(id)).one_or_none():
            data['status'] = 900
            data['msg'] = 'mentor is deleted'
            return data

        # 如果用户还没登录
        elif user.is_login == 0:
            data['status'] = 403
            data['msg'] = 'please login first'
            return data

        # 用户登录了可以正常logout
        else:
            user.is_login = 0
            user.save()

        return data
'''

# /mentors/<int:id>/logout/
class MentorsLogout(Resource):

    @authm.login_required

    def get(self, id):
        data = {
            "status": 201,
            "msg": 'mentor logout ok'
        }

        user = Mentors.query.get(id)

        # 如果id不存在
        if not Mentors.query.filter(Mentors.mentor_id.__eq__(id)).one_or_none():
            data['status'] = 900
            data['msg'] = 'mentor is deleted'
            return data

        # 如果用户还没登录
        elif user.is_login == 0:
            data['status'] = 403
            data['msg'] = 'please login first'
            return data

        # 只能操作自己的账号


        # 用户登录了可以正常logout
        else:
            user.is_login = 0
            user.save()

        return data




# —————————————————————————— Students 注册和登录—————————————————————————————— #
students_fields = {
    'student_id': fields.Integer,
    'student_name': fields.String,
    'lab_id': fields.Integer
    #'student_permission': fields.Integer,
}

# 外层输出参数格式化
response_students_fields = {
    'status': fields.Integer,
    'msg': fields.String,
    'data': fields.Nested(students_fields)
}


# 外层输出参数格式化  + token
response_students_token_fields = {
    'status': fields.Integer,
    'msg': fields.String,
    'token': fields.String,
    'data': fields.Nested(students_fields)
}


# /students/register/
class StudentsRegister(Resource):
    @authm.login_required
    def post(self):
        #global user
        parser = reqparse.RequestParser()
        parser.add_argument('u_name', required=True, help="请输入用户名")
        parser.add_argument('u_password', required=True, help="请输入密码")
        parser.add_argument('l_id', required=True, help="请输入lab_id")
        args = parser.parse_args()

        #users = args.get("user")
        #action = args.get("action")
        u_name = args.get("u_name")
        u_password = args.get("u_password")
        l_id = args.get("l_id")

        #global data
        data = {
            "status": 201,
            "msg": 'student register ok'
        }

        user = Students()

        # 防止重复注册
        if user.query.filter(Students.student_name.__eq__(u_name)).one_or_none():
            data['status'] = 403
            data['msg'] = 'student has already registered'
            return data

        else:
            # register_students(user, u_name, u_password)
            user.student_name = u_name

            # 密码做数据安全处理

            user.student_password = user.stu_password(u_password)
            user.lab_id = l_id
            user.save()

            data['data'] = user

            return marshal(data, response_students_token_fields)

    # eg. curl http://localhost:5000/students/register/
    def get(self):
        return marshal(data, response_students_token_fields)


# /students/login/
class StudentsLogin(Resource):

    def post(self):
        parser = reqparse.RequestParser()
        parser.add_argument('u_name', required=True, help="请输入用户名")
        parser.add_argument('u_password', required=True, help="请输入密码")

        global user

        args = parser.parse_args()

        #users = args.get("user")
        #action = args.get("action")
        u_name = args.get("u_name")
        u_password = args.get("u_password")

        global data
        data = {
            "status": 201,
            "msg": 'student login ok'
        }

        #token = request.args.get("token")
        #if token:
            #abort(401, message="User has already login.")
        #else:
        user = Students.query.filter(Students.student_name.__eq__(u_name)).one_or_none()

        #login_students(user, u_password)

        if user:  # 如果用户存在

            # 如果用户已经登录
            if user.is_login:
                data['status'] = 403
                data['msg'] = 'student is login'
                return data

            # 如果密码错误
            if not user.verify_password(u_password):
                data['status'] = 406
                data['msg'] = 'password fail'
                return data

            # 如果用户已被删除
            elif user.is_delete:
                data['status'] = 900
                data['msg'] = 'student is deleted'
                return data

            else:
                g.user = user  # 赋给全局

                data['data'] = user

                token = user.generate_auth_token(600)  #生成token
                # token = str(uuid.uuid4())  # token 需要转换为字符串

                # 将用户token 存到缓存中 可以根据token 找到用户id 也可以根据用户id 找到token
                # key: 使用token  值:用户id
                # 第一个参数是键，这个主要是用来获取这个缓存的值。第二个参数是值。第三个参数是秒
                #cache.set(token, user.student_id, timeout=60*60*24*7)
                #if not cache.get(token):
                #   abort(403, message="fail to set token")
                data['token'] = token
                user.is_login = True
                user.save()
                return marshal(data, response_students_token_fields)

        # 如果用户不存在
        else:
            data['status'] = 406
            data['msg'] = 'student not exist'
            #return data

        data['data'] = user
        return marshal(data, response_students_token_fields)

    #eg. curl http://localhost:5000/students/register/
    def get(self):
        return marshal(data, response_students_token_fields)


# /students/<int:id>/
class StudentUser(Resource):
    # 根据 id 获取用户信息
    @auths.login_required
    @marshal_with(response_students_fields)
    def get(self, id):
        user = Students.query.get(id)

        data = {
            "status": 200,
            "msg": 'ok',
            'data': user,
        }
        return data

    # 根据 id 修改用户信息 --> 密码修改
    @auths.login_required
    @marshal_with(response_students_fields)
    def post(self, id):
        parser = reqparse.RequestParser()
        parser.add_argument('u_password', required=True, help="请输入修改后的密码")
        args = parser.parse_args()

        u_password = args.get("u_password")

        user = Students.query.get(id)  # 根据id获得用户

        user.student_password = user.stu_password(u_password)

        user.save()

        data = {
            "status": 200,
            "msg": 'password change ok',
            'data': user
        }
        return data

    # 根据 id 删除某个用户   Model中设计一个字段 is_delete 来判断是否已删除
    @auths.login_required
    @marshal_with(response_students_fields)
    def delete(self, id):
        user = Students.query.get(id)

        user.is_delete = True  # is_delete = 1  表示删除用户

        user.save()

        data = {
            "status": 200,
            "msg": 'delete ok',
            "data": user
        }
        return data


# /students/<int:id>/logout/
class StudentsLogout(Resource):

    @auths.login_required
    def get(self, id):
        data = {
            "status": 201,
            "msg": 'student logout ok'
        }

        user = Students.query.get(id)

        # 如果id不存在
        if not Students.query.filter(Students.student_id.__eq__(id)).one_or_none():
            data['status'] = 900
            data['msg'] = 'student is deleted'
            return data

        # 如果用户还没登录
        elif user.is_login == 0:
            data['status'] = 403
            data['msg'] = 'please login first'
            return data

        # 用户登录了可以正常logout
        else:
            user.is_login = 0
            user.save()

        return data



"""

def login_mentors(user, u_password):

    if user:

        if not user.verify_password(u_password):

            data['status'] = 406
            data['msg'] = 'password fail'
            return data

        elif user.is_delete:
            data['status'] = 900
            data['msg'] = 'user is deleted'
            return data

        else:

            data['data'] = user

            token = user.generate_auth_token(600)
            #token = str(uuid.uuid4())  # token 需要转换为字符串

            # 将用户token 存到缓存中 可以根据token 找到用户id 也可以根据用户id 找到token
            # key: 使用token  值:用户id
            # 第一个参数是键，这个主要是用来获取这个缓存的值。第二个参数是值。第三个参数是秒
            #cache.set(token, user.mentor_id, timeout=60*60*24*7)
            #if not cache.get(token):
            #    abort(403, message="fail to set token")
            data['token'] = token

            return marshal(data, response_mentors_token_fields)

    else:
        data['status'] = 406
        data['msg'] = 'user not exist'
        return data


def register_mentors(user, u_name, u_password):

    user.mentor_name = u_name

    # 密码做数据安全处理
    # user.set_password(u_password)

    # 最终方法  密码做数据安全处理

    user.mentor_password = user.men_password(u_password)

    user.save()


# 用户注册登录 操作  其中密码做了数据安全
class UsersResource(Resource):

    def post(self):
        global user

        args = parser.parse_args()

        users = args.get("user")
        action = args.get("action")
        u_name = args.get("u_name")
        u_password = args.get("u_password")

        global data
        data = {
            "status": 201,
            "msg": 'ok'
        }

        if users == "mentors":

            #def login(User, u_name, u_password, data)
            if action == "login":       # 用户登录
                token = request.args.get("token")
                if token:
                    abort(401, message="User has already login.")
                else:
                    user = Mentors.query.filter(Mentors.mentor_name.__eq__(u_name)).one_or_none()

                    login_mentors(user, u_password)


            elif action == "register":   # 用户注册

                #def register(User, u_name, u_password)
                user = Mentors()
                register_mentors(user, u_name, u_password)


           # elif action == "logout":  # 用户登出
               # user = Mentors()
               # cache.


        else:
            pass

        data['data'] = user
        return marshal(data, response_mentors_token_fields)
        #return data

    def get(self):
        return marshal(data, response_mentors_token_fields)



# 更新用户信息不更改用户名，只改密码
parser_user = reqparse.RequestParser()
parser_user.add_argument('u_password', required=True, help='请输入新密码')





# 单个用户数据操作  查询 修改 删除
class UserResource(Resource):
    # 根据 id 获取用户信息
    @marshal_with(response_user_fields)
    def get(self, id):

        user = User.query.get(id)

        data = {
            "status": 200,
            "msg": 'ok',
            'data': user,
        }
        return data

    # 根据 id 修改用户信息 --> 密码修改
    @marshal_with(response_user_fields)
    def post(self, id):

        args = parser_user.parse_args()

        u_password = args.get("u_password")

        user = User.query.get(id)

        user.u_password = u_password

        user.save()

        data = {
            "status": 200,
            "msg": 'password change ok',
            'data': user,
        }
        return data

    # 根据 id 删除某个用户   Model中应该设计一个字段 is_delete 来判断是否已删除
    @marshal_with(response_user_fields)
    def delete(self, id):

        user = User.query.get(id)

        user.is_delete = True       # is_delete = 1  表示删除用户

        user.save()

        data = {
            "status": 200,
            "msg": 'delete ok',
            "data": user,
        }
        return data
"""