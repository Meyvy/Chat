import json
from traceback import print_tb
import time
import requests
import socket
from project import crypto
import os.path


def check_data(data,other_pk,sym_sk):
    if not crypto.rsa_verify(eval(data['signature']), data['message'], other_pk):
        print('signature is not valid!')
        exit()
    return crypto.sym_dec(eval(data['message']),sym_sk)

def process_first_message(first_message, url_get_user, server_pk,):
    r = requests.get(url_get_user.format(user=first_message['user_name']))

    if r.status_code != 200:
        print('something went wrong!')
        print(r.text)
        exit()

    res = eval(r.text)

    if not crypto.rsa_verify(eval(res['user_name_sig']), res['user_name'], server_pk):
        print('signature is not valid!')
        exit()

    if not crypto.rsa_verify(eval(res['name_sig']), res['name'], server_pk):
        print('signature is not valid!')
        exit()

    if not crypto.rsa_verify(eval(res['email_sig']), res['email'], server_pk):
        print('signature is not valid!')
        exit()
    if not crypto.rsa_verify(eval(res['public_key_sig']), eval(res['public_key']), server_pk):
        print('signature is not valid!')
        exit()

    other_pk = crypto.serialization.load_pem_public_key(
        eval(res['public_key'])
    )
    if not crypto.rsa_verify(eval(first_message['user_name_sig']), first_message['user_name'], other_pk):
        print('signature is not valid!')
        exit()

    if not crypto.rsa_verify(eval(first_message['name_sig']), first_message['name'], other_pk):
        print('signature is not valid!')
        exit()

    if not crypto.rsa_verify(eval(first_message['email_sig']), first_message['email'], other_pk):
        print('signature is not valid!')
        exit()
    if not crypto.rsa_verify(eval(first_message['share_public_key_sig']), first_message['share_public_key'], other_pk):
        print('signature is not valid!')
        exit()
    if res['user_name'] != first_message['user_name']:
        print('inconsistent data!')
        exit()
    if res['name'] != first_message['name']:
        print('inconsistent data!')
        exit()
    if res['email'] != first_message['email']:
        print('inconsistent data!')
        exit()


def create_message(msg, sk, sym_sk):
    msg = repr(crypto.sym_enc(msg, sym_sk))
    sig = repr(crypto.rsa_sign(msg, sk))
    data = {
        'message': msg,
        'signature': sig
    }
    return json.dumps(data).encode()


url_get_user = 'http://127.0.0.1:5000/user/{user}'

server_pk = crypto.read_rsa_public_key(
    '/home/meyvy/Documents/studies/uni/term6/cryptography/code/project/public_server_key.pem')
check = os.path.isfile(
    '/home/meyvy/Documents/studies/uni/term6/cryptography/code/project/client/config.txt')
if check != True:
    print('please run setup.py first')
    exit()


with open('/home/meyvy/Documents/studies/uni/term6/cryptography/code/project/shared_param.pem', "rb") as key_file:
    param = crypto.serialization.load_pem_parameters(
        key_file.read()
    )



f = open('/home/meyvy/Documents/studies/uni/term6/cryptography/code/project/client/config.txt')

content = f.readlines()
user_name = content[0][:-1]
name = content[1][:-1]
email = content[2][:-1]
port = int(content[3][:-1])
id = int(content[4])

sk = crypto.read_rsa_private_key(
    '/home/meyvy/Documents/studies/uni/term6/cryptography/code/project/client/client_private_key.pem')
pk = crypto.read_rsa_public_key(
    '/home/meyvy/Documents/studies/uni/term6/cryptography/code/project/client/client_public_key.pem')

other_name = input('who do you want to send a  message to?:')

r = requests.get(url_get_user.format(user=other_name))

if r.status_code != 200:
    print('something went wrong!')
    print(r.text)
    exit()

res = eval(r.text)

if not crypto.rsa_verify(eval(res['user_name_sig']), res['user_name'], server_pk):
    print('signature is not valid!1')
    exit()

if not crypto.rsa_verify(eval(res['name_sig']), res['name'], server_pk):
    print('signature is not valid!2')
    exit()

if not crypto.rsa_verify(eval(res['email_sig']), res['email'], server_pk):
    print('signature is not valid!3')
    exit()
if not crypto.rsa_verify(eval(res['public_key_sig']), eval(res['public_key']), server_pk):
    print('signature is not valid!4')
    exit()
if not crypto.rsa_verify(eval(res['port_number_sig']), str(res['port_number']), server_pk):
    print('signature is not valid!5')
    exit()
print(res['port_number'])

print('details:\n')
print('username={user} \t name={name}\n'.format(user=res['user_name'], name=res['name']),
      'email={email} \t port={port}\n'.format(
          email=res['email'], port=res['port_number']),
      'public_key={pk}\n'.format(pk=res['public_key']))

other_pk = crypto.serialization.load_pem_public_key(
        eval(res['public_key'])
    )

order = input('do you want to continue?[y/n]:\n')
while order != 'y' and order != 'n':
    oredr = 'please choose a valid option:\n'
if order == 'n':
    print('Goodbye')
    exit()

share_private_key = param.generate_private_key()
share_public_key = share_private_key.public_key()

first_message = {}
first_message['user_name'] = user_name
first_message['name'] = name
first_message['email'] = email
first_message['share_public_key'] = repr(share_public_key.public_bytes(
    encoding=crypto.serialization.Encoding.PEM,
    format=crypto.serialization.PublicFormat.SubjectPublicKeyInfo
))
first_message['user_name_sig'] = repr(crypto.rsa_sign(user_name, sk))
first_message['name_sig'] = repr(crypto.rsa_sign(name, sk))
first_message['email_sig'] = repr(crypto.rsa_sign(email, sk))
first_message['share_public_key_sig'] = repr(
    crypto.rsa_sign(first_message['share_public_key'], sk))

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

sock.connect(('127.0.0.1', res['port_number']))


sock.send(json.dumps(first_message).encode())



first_message = eval(sock.recv(10000).decode())


process_first_message(first_message,url_get_user,server_pk)

listen_public=crypto.serialization.load_pem_public_key(
    eval(first_message['share_public_key'])
)

sym_sk=crypto.HKDF(
    algorithm=crypto.hashes.SHA512(),
    length=32,
    salt=None,
    info=b'handshake data',
).derive(share_private_key.exchange(listen_public))

sym_sk=(sym_sk,sym_sk[16:])
print(len(sym_sk))

while True:
    msg = input('You:')
    print('You(encrypted):{d}'.format(d=repr(crypto.sym_enc(msg,sym_sk))))
    sock.send(create_message(msg,sk,sym_sk))
    
    data = eval(sock.recv(10000).decode())
    print('Other:{d}'.format(d=data['message']))
    data=check_data(data,other_pk,sym_sk)
    print('Other(decrypted):{d}'.format(d=data))
