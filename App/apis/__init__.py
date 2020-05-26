from flask_restful import Api


from App.apis.BookApi import BookResource
from App.apis.CodeApi import CodeResource
from App.apis.HelloApi import Hello
from App.apis.MovieApi import MovieResource, MoviesResource
from App.apis.UserApi import *

api = Api()


def init_api(app):
    api.init_app(app=app)

api.add_resource(Hello, "/")
api.add_resource(CodeResource,"/codes/")
# Lab 注册
# eg. curl http://localhost:5000/labs/register/ -d "l_name=b" -d "l_info=234" -X POST -v
api.add_resource(LabsRegister, "/labs/register/")

# eg. curl -d "l_name=new_b" -d "l_info=new_234" -X POST -H "Authorization: Mistlab1 <token>" http://localhost:5000/labs/modify/1/
api.add_resource(Labsmodify, "/labs/modify/<int:id>/")

# mentors 注册/登录/登出
# eg. curl http://localhost:5000/mentors/register/ -d "u_name=c" -d "u_password=234" -d "l_id=1" -X POST -v
api.add_resource(MentorsRegister, "/mentors/register/")
# eg. curl http://localhost:5000/mentors/login/ -d "u_name=c" -d "u_password=111" -X POST -v
api.add_resource(MentorsLogin, "/mentors/login/")
# eg. curl -X GET -H "Authorization: Mistlab1 <token>" http://localhost:5000/mentors/1/logout/
api.add_resource(MentorsLogout, "/mentors/<int:id>/logout/")

# 读取和删除单个mentor用户/修改密码
# 读取mentor信息eg. curl -X GET -H "Authorization: Mistlab1  <token>" http://localhost:5000/mentors/1/
# 修改密码eg. curl -d 'u_password=111' -X POST -H "Authorization: Mistlab1 <token>" http://localhost:5000/mentors/1/
# 删除mentor用户eg. curl -X DELETE -H "Authorization: Mistlab1 <token>" http://localhost:5000/mentors/1/
api.add_resource(MentorUser, "/mentors/<int:id>/")



# students 注册/登录/登出
# eg. curl http://localhost:5000/students/register/ -d "u_name=b" -d "u_password=234" -d "l_id=1" -X POST -v
api.add_resource(StudentsRegister, "/students/register/")
# eg. curl http://localhost:5000/students/login/ -d "u_name=b" -d "u_password=234" -X POST -v
api.add_resource(StudentsLogin, "/students/login/")
# eg. curl -X GET -H "Authorization: Mistlab2 <token>" http://localhost:5000/students/1/logout/
api.add_resource(StudentsLogout, "/students/<int:id>/logout/")

# 读取和删除单个student用户/修改密码
# 读取student信息eg. curl -X GET -H "Authorization: Mistlab2  <token>" http://localhost:5000/students/1/
# 修改密码eg. curl -d 'u_password=111' -X POST -H "Authorization: Mistlab2 <token>" http://localhost:5000/mentors/1/
# 删除student用户eg. curl -X DELETE -H "Authorization: Mistlab2 <token>" http://localhost:5000/students/1/
api.add_resource(StudentUser, "/students/<int:id>/")






#api.add_resource(UsersResource, "/users/")
#api.add_resource(UserResource, "/user/<int:id>/")
#api.add_resource(BookResource,"/books/")

#api.add_resource(CodeResource,"/codes/")
