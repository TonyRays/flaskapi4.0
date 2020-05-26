from flask_restful import Resource
from App.models.UserModel import *
from App.apis.ApiDecorator import login_required, check_permission, check_permission_new
from itsdangerous import TimedJSONWebSignatureSerializer, BadSignature,\
    SignatureExpired

class Hello(Resource):
    #@login_required
        # 判断是否有读权限
    #@check_permission(READ)
    #@authm.verify_token
    #@check_permission(READ)
    def get(self):
        return {"msg": 'Hello get'}

    @check_permission(READ)
    #@login_required
    def post(self):
        return {"msg": 'Hello post'}

    def delete(self):
        return {"msg": 'Hello delete'}

    def put(self):
        return {"msg": 'Hello put'}