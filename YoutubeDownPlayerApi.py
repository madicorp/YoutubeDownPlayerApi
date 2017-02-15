#!/usr/bin/env python
import os
from flask import Flask, abort, request, jsonify, g, url_for
from flask_sqlalchemy import SQLAlchemy
from flask_httpauth import HTTPBasicAuth
from passlib.apps import custom_app_context as pwd_context
from itsdangerous import (TimedJSONWebSignatureSerializer
                          as Serializer, BadSignature, SignatureExpired)
from pytube import YouTube
import yaml

ROOT_DIR = os.path.dirname(os.path.abspath(__file__))


def get_config():
    with open(ROOT_DIR + '/config.yml') as file:
        return yaml.load(file)


# initialization
app = Flask(__name__)
configs = get_config()
app.config['SECRET_KEY'] = configs['SECRET_KEY']
app.config['SQLALCHEMY_DATABASE_URI'] = configs['SQLALCHEMY_DATABASE_URI']
app.config['SQLALCHEMY_COMMIT_ON_TEARDOWN'] = configs['SQLALCHEMY_COMMIT_ON_TEARDOWN']

# extensions
db = SQLAlchemy(app)
auth = HTTPBasicAuth()


class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(32), index=True)
    password_hash = db.Column(db.String(64))

    def hash_password(self, password):
        self.password_hash = pwd_context.encrypt(password)

    def verify_password(self, password):
        return pwd_context.verify(password, self.password_hash)

    def generate_auth_token(self, expiration=600):
        s = Serializer(app.config['SECRET_KEY'], expires_in=expiration)
        return s.dumps({'id': self.id})

    @staticmethod
    def verify_auth_token(token):
        s = Serializer(app.config['SECRET_KEY'])
        try:
            data = s.loads(token)
        except SignatureExpired:
            return None  # valid token, but expired
        except BadSignature:
            return None  # invalid token
        user = User.query.get(data['id'])
        return user


class Videos(db.Model):
    __tablename__ = 'videos'
    id = db.Column(db.Integer, primary_key=True)
    video_id = db.Column(db.String(32), index=True)
    description = db.Column(db.String(64))
    filename = db.Column(db.String(64))


@auth.verify_password
def verify_password(username_or_token, password):
    # first try to authenticate by token
    user = User.verify_auth_token(username_or_token)
    if not user:
        # try to authenticate with username/password
        user = User.query.filter_by(username=username_or_token).first()
        if not user or not user.verify_password(password):
            return False
    g.user = user
    return True


@app.route('/api/users', methods=['POST'])
def new_user():
    username = request.json.get('username')
    password = request.json.get('password')
    if username is None or password is None:
        abort(400)  # missing arguments
    if User.query.filter_by(username=username).first() is not None:
        abort(400)  # existing user
    user = User(username=username)
    user.hash_password(password)
    db.session.add(user)
    db.session.commit()
    return (jsonify({'username': user.username}), 201,
            {'Location': url_for('get_user', id=user.id, _external=True)})


@app.route('/api/users/<int:id>')
def get_user(id):
    user = User.query.get(id)
    if not user:
        abort(400)
    return jsonify({'username': user.username})


@app.route('/api/token')
@auth.login_required
def get_auth_token():
    token = g.user.generate_auth_token(600)
    return jsonify({'token': token.decode('ascii'), 'duration': 600})


@app.route('/api/resource/<string:videoid>')
@auth.login_required
def get_resource(videoid):
    video = Videos.query.filter_by(video_id=videoid).first()
    if video is None:
        yt = YouTube("http://www.youtube.com/watch?v=" + videoid)
        filename = yt.filename
        yt.set_filename(videoid)
        yt_video = yt.get('mp4')
        yt_video.download(ROOT_DIR + '/static/')
        video = Videos()
        video.filename = videoid + '.mp4'
        video.video_id = videoid
        video.description = filename
        db.session.add(video)
        db.session.commit()

    return jsonify({'filename': video.filename, 'description': video.description, 'id': video.video_id,
                    'url': url_for('static', filename=video.filename)})


if __name__ == '__main__':
    if not os.path.exists('db.sqlite'):
        db.create_all()
    app.run(debug=True)
