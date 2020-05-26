# coding=utf-8
import hashlib

from werkzeug.security import generate_password_hash, check_password_hash
from flask_httpauth import HTTPBasicAuth, HTTPTokenAuth, MultiAuth
from flask import abort
from itsdangerous import TimedJSONWebSignatureSerializer as Serializer
from itsdangerous import  BadSignature,SignatureExpired

from App.ext import db
from App.models.ModelUtil import BaseModel
from datetime import datetime
import jwt
import time


skey = 'top secret!'
token_serializer = Serializer(skey, expires_in=360000)
authm = HTTPTokenAuth('Mistlab1')
auths = HTTPTokenAuth('Mistlab2')



# 权限判定
# 读
READ = 1
# 赞
PRAISE = 2
# 写
WRITE = 4


# Table
# Labs table
class Labs(BaseModel, db.Model):
    __tablename__ = 'Labs'

    lab_id = db.Column(db.Integer(), primary_key=True)
    lab_name = db.Column(db.String(50))
    lab_info = db.Column(db.String(1000))
    lab_time = db.Column(db.DateTime, nullable=False, default=datetime.now())
    is_delete = db.Column(db.Boolean, default=False)
    has_mentor = db.Column(db.Boolean, default=False)
    

    def __repr__(self):
        return '<Labs %r>' % self.lab_name

'''
# Table
# room table
class Room(BaseModel, db.Model):
    __tablename__ = 'room'

    room_id = db.Column(db.Integer(), primary_key=True)
    room_name = db.Column(db.String(50))
    room_info = db.Column(db.String(1000))
    room_time = db.Column(db.DateTime, nullable=False, default=datetime.now())
    is_delete = db.Column(db.Boolean, default=False)
    # has_mentor = db.Column(db.Boolean, default=False)
    
    #权限
    #student_id_0 = db.column(db.Integer(), nullable = True, default = 0)
#    Student_id_access = db.Column(db.Integer(), db.ForeignKey("student_access.id"))
    #mentor_id_0 = db.column(db.Integer(), nullable = True, default = 0)
#    Mentor_id_access = db.Column(db.Integer(), db.ForeignKey("mentor_access.id"))

    def __repr__(self):
        return '<Labs %r>' % self.lab_name

class student_access(Base):
    __tablename__ = 'student_access'
    room_id = Column(Integer, primary_key=True)
    student_id = Column(db.Integer(), default= 0)

class mentor_access(Base):
    __tablename__ = 'mentor_access'
    room_id = Column(Integer, primary_key=True)
    mentor_id = Column(db.Integer(), default= 0)
'''

# Mentors table
class Mentors(BaseModel, db.Model):
    __tablename__ = 'Mentors'

    mentor_id = db.Column(db.Integer(), primary_key=True)
    mentor_name = db.Column(db.String(50))
    mentor_password = db.Column(db.String(128))
    lab_id = db.Column(db.Integer(), db.ForeignKey('Labs.lab_id'))
    is_delete = db.Column(db.Boolean, default=False)
    is_login = db.Column(db.Boolean, default=False)

    # 密码hash加密
    def men_password(self, password):
        self.mentor_password = generate_password_hash(password)
        return self.mentor_password

    # 验证密码
    def verify_password(self, password):
        return check_password_hash(self.mentor_password, password)

    # 生成token
    def generate_auth_token(self, expires_in=600):
        return token_serializer.dumps({'id': self.mentor_id}).decode('utf-8')

    # 验证token
    @authm.verify_token
    def verify_auth_token(token):
        try:
            data = token_serializer.loads(token)
            # data = jwt.decode(token, secret_key, algorithms=['HS256'])
        except:
            return False
        if 'id' in data:
            return Mentors.query.get(data['id'])

    # 权限判定
    def check_permission(self, permission):
        return self.mentor_password & permission == permission

    def __repr__(self):
        return '<Mentors %r>' % self.mentor_name


class Students(BaseModel, db.Model):
    __tablename__ = 'Students'

    student_id = db.Column(db.Integer(), primary_key=True)
    student_name = db.Column(db.String(50))
    student_password = db.Column(db.String(128))
    lab_id = db.Column(db.Integer(), db.ForeignKey('Labs.lab_id'))
    admin = db.Column(db.Boolean, default=False)
    is_delete = db.Column(db.Boolean, default=False)
    is_login = db.Column(db.Boolean, default=False)

    # 密码hash加密
    def stu_password(self, password):
        self.student_password = generate_password_hash(password)
        return self.student_password

    # 验证密码
    def verify_password(self, password):
        return check_password_hash(self.student_password, password)

    # 生成token
    def generate_auth_token(self, expires_in=600):
        return token_serializer.dumps({'id': self.student_id}).decode('utf-8')

    # 验证token
    @auths.verify_token
    def verify_auth_token(token):
        try:
            data = token_serializer.loads(token)
            # data = jwt.decode(token, secret_key, algorithms=['HS256'])
        except:
            return False
        if 'id' in data:
            return Students.query.get(data['id'])

    # 权限判定
    def check_permission(self, permission):
        return self.student_password & permission == permission

    def __repr__(self):
        return '<students %r>' % self.student_name