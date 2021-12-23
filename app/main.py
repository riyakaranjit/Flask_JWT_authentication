from flask import Flask, request, jsonify, make_response
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
import uuid
import jwt
import datetime
from functools import wraps

app = Flask(__name__)

app.config['SECRET_KEY'] = 'my_secret_key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///ssample.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = True

db = SQLAlchemy(app)


class Users(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    public_id = db.Column(db.Integer)
    name = db.Column(db.String(50))
    password = db.Column(db.String(50))
    jwt_token = db.Column(db.Text(), nullable=True)


def token_required(f):
    @wraps(f)
    def decorator(*args, **kwargs):

        token = None

        if 'x-access-tokens' in request.headers:
            token = request.headers['x-access-tokens']

        if not token:
            return jsonify({'message': 'a valid token is missing'})

        try:
            data = jwt.decode(token, app.config['SECRET_KEY'])
            current_user = Users.query.filter_by(public_id=data['public_id']).first()

            if current_user.jwt_token == '':
                return jsonify({"message": 'token expired. log in again.'}), 401
        except:
            import traceback

            traceback.print_exc()
            return jsonify({'message': 'token is invalid'}), 401

        return f(current_user, *args, **kwargs)

    return decorator


@app.route('/register', methods=['GET', 'POST'])
def signup_user():
    data = request.get_json(force=True)
    print(data)

    hashed_password = generate_password_hash(data['password'], method='sha256')

    new_user = Users(public_id=str(uuid.uuid4()), name=data['name'], password=hashed_password)
    db.session.add(new_user)
    db.session.commit()

    return jsonify({'message': 'registered successfully'})


@app.route('/login', methods=['GET', 'POST'])
def login_user():
    auth = request.authorization
    print(auth)

    if not auth or not auth.username or not auth.password:
        return jsonify({"message": "Please provide username and password to authenticate"}), 401

    user = Users.query.filter_by(name=auth.username).first()

    if check_password_hash(user.password, auth.password):
        token = jwt.encode(
            {'public_id': user.public_id, 'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=30)},
            app.config['SECRET_KEY'])

        user.jwt_token = token.decode("UTF-8")
        db.session.commit()
        return jsonify({'token': token.decode("UTF-8")}), 200

    return jsonify({"message": 'unauthorized access'}), 403


@app.route('/logout', methods=['GET', 'POST'])
@token_required
def logout_user(current_user):
    current_user.jwt_token = ''
    db.session.commit()
    return jsonify({"message": "logout successful"}), 200


@app.route('/my_info', methods=['GET', 'POST'])
@token_required
def get_my_info(current_user):
    info = dict(name=current_user.name)
    return jsonify({'my info': info})


@app.route('/', methods=['GET', 'POST'])
def api_test():
    return jsonify({"message":"API works!"}),200


if __name__ == '__main__':
    db.create_all()
    app.run(debug=True)
