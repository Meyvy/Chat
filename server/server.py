
import imp
import importlib
import json
from crypt import methods
from flask import Flask, request, jsonify, url_for
from project import crypto
from project.server import database
from itsdangerous import URLSafeTimedSerializer, SignatureExpired, BadSignature
from flask_mail import Mail, Message


def check(data, index, exist):
    if data.get(index) == None:
        return '{index} is not specfied'.format(index=index), 400
    if exist(data[index]):
        return 'this {index} already exists!'.format(index=index), 400
    return True


path_to_sk = '/home/meyvy/Documents/studies/uni/term6/cryptography/code/project/server/private_server_key.pem'
path_to_pk = '/home/meyvy/Documents/studies/uni/term6/cryptography/code/project/public_server_key.pem'

sk = crypto.read_rsa_private_key(path_to_sk)
pk = crypto.read_rsa_public_key(path_to_pk)

app = Flask(__name__)
app.config['SECRET_KEY'] = ''
app.config['SALT'] = ''
app.config['MAIL_SERVER'] = ''
app.config['MAIL_PORT'] = 
app.config['MAIL_USERNAME'] = ''
app.config['MAIL_PASSWORD'] = ''
app.config['MAIL_USE_TLS'] = False
app.config['MAIL_USE_SSL'] = True
mail = Mail(app)
ts = URLSafeTimedSerializer(app.config["SECRET_KEY"])


@app.route('/user/<user_name>', methods=['GET'])
def handle_user(user_name):
    user = {}
    if not database.user_name_exists(user_name):
        return 'User does not exist', 400
    if not database.verified(user_name):
        return 'User is not verified', 400
    res = database.get_user(user_name)
    user['user_name'] = res[1]
    user['name'] = res[2]
    user['email'] = res[3]
    user['public_key'] = res[4]
    user['port_number'] = res[6]
    user['user_name_sig'] = repr(crypto.rsa_sign(res[1], sk))
    user['name_sig'] = repr(crypto.rsa_sign(res[2], sk))
    user['email_sig'] = repr(crypto.rsa_sign(res[3], sk))
    user['public_key_sig'] = repr(crypto.rsa_sign(res[4], sk))
    user['port_number_sig'] = repr(crypto.rsa_sign(str(res[6]), sk))
    return jsonify(user_name=user['user_name'], name=user['name'], email=user['email'],
                   public_key=repr(user['public_key']), port_number=user['port_number'],
                   user_name_sig=user['user_name_sig'], name_sig=user['name_sig'],
                   email_sig=user['email_sig'], public_key_sig=user['public_key_sig'],
                   port_number_sig=user['port_number_sig']
                   )


@app.route('/register', methods=['POST'])
def handle_register():
    content_type = request.content_type
    if content_type != 'application/json':
        return 'Invaid request type', 400
    data = request.json
    if data.get('user_name') == None:
        return 'user_name is not specified', 400
    if data.get('public_key') == None:
        return 'public_key is not specified', 400
    if data.get('name') == None:
        return 'name is not specified', 400
    if data.get('email') == None:
        return 'email is not specified', 400
    if data.get('user_name_sig') == None:
        return 'No signature for user_name'
    if data.get('name_sig') == None:
        return 'No signature for name'
    if data.get('email_sig') == None:
        return 'No signature for email_sig'
    if database.user_name_exists(data['user_name']):
        return 'user_name already exists', 400
    if database.email_exists(data['email']):
        return 'email already exists', 400
    client_pk = crypto.serialization.load_pem_public_key(
        eval(data['public_key'])
    )
    if not crypto.rsa_verify(eval(data['user_name_sig']), data['user_name'], client_pk):
        return 'The signature is not valid for usernme'
    if not crypto.rsa_verify(eval(data['name_sig']), data['name'], client_pk):
        return 'The signature is not valid for name'
    if not crypto.rsa_verify(eval(data['email_sig']), data['email'], client_pk):
        return 'The signature is not valid for email'

    id, port = database.insert_user(user_name=data['user_name'], name=data['name'],
                                    email=data['email'], public_key=data['public_key'])
    sig_id = repr(crypto.rsa_sign(str(id), sk))
    sig_port = repr(crypto.rsa_sign(str(port), sk))
    return jsonify(id=id, sig_id=sig_id, port=port, sig_port=sig_port)


@app.route('/verify', methods=['POST'])
def handle_verify():
    content_type = request.content_type
    if content_type != 'application/json':
        return 'Invaid request type', 400
    data = request.json
    if data.get('user_name') == None:
        return 'user_name is not specified', 400
    if data.get('email') == None:
        return 'email is not specified', 400
    if not database.user_name_exists(data['user_name']):
        return 'user_name does not exist', 400
    if not database.email_exists(data['email']):
        return 'email does not  exist', 400
    user = database.get_user(data['user_name'])

    if user[3] != data['email']:
        return 'user_name and email dont match', 400
    client_pk = crypto.serialization.load_pem_public_key(
        eval(data['public_key'])
    )
    if not crypto.rsa_verify(eval(data['name_sig']), data['name'], client_pk):
        return 'The signature is not valid for name', 400
    if not crypto.rsa_verify(eval(data['user_name_sig']), data['user_name'], client_pk):
        return 'The signature is not valid for username', 400
    if not crypto.rsa_verify(eval(data['email_sig']), data['email'], client_pk):
        return 'The signature is not valid for email', 400
    email = data['email']
    token = ts.dumps(email, salt=app.config['SALT'])
    msg = Message('Confirm Email',
                  sender='mohamadrezaeyvazi@yahoo.com', recipients=[email])
    msg.body = token
    mail.send(msg)
    return 'Confrim your email'


@app.route('/confirm_email/<token>', methods=['GET'])
def handle_token(token):
    try:
        email = ts.loads(token, salt=app.config['SALT'], max_age=60*10)
        database.validate(email)
        return 'You have been confirmed!'
    except SignatureExpired as err:
        return 'token expired!'
    except BadSignature as err:
        return 'wrong link!'


@app.route('/')
def index():
    content_type = request.content_type
    if content_type != 'application/json':
        return 'Invaid request type', 400
    return request.json


if __name__ == '__main__':
    app.run(debug=True)
