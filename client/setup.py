import json
import cryptography
import requests
from project import crypto
import os.path


url_register='http://127.0.0.1:5000/register'
url_verify='http://127.0.0.1:5000/verify'
url_email_confirm='http://127.0.0.1:5000/confirm_email/{token}'

data={}
check=os.path.isfile('/home/meyvy/Documents/studies/uni/term6/cryptography/code/project/client/config.txt')
if check==True:
    print('The user has already set up')
    exit() 


sk,pk=crypto.rsa_key()
spk=crypto.seriliaze_rsa_public_key(pk)
crypto.write('/home/meyvy/Documents/studies/uni/term6/cryptography/code/project/client/client_private_key.pem',crypto.seriliaze_rsa_private_key(sk))
crypto.write('/home/meyvy/Documents/studies/uni/term6/cryptography/code/project/client/client_public_key.pem',spk)

server_pk=crypto.read_rsa_public_key('/home/meyvy/Documents/studies/uni/term6/cryptography/code/project/public_server_key.pem')

user_name=input('please enter a username:')

name=input('please enter your name:')

email=input('please enter your email:')

data['user_name']=user_name
data['name']=name
data['email']=email
data['user_name_sig']=repr(crypto.rsa_sign(user_name,sk))
data['name_sig']=repr(crypto.rsa_sign(name,sk))
data['email_sig']=repr(crypto.rsa_sign(email,sk))
data['public_key']=repr(spk)

headers = {'content-type': 'application/json'}

r=requests.post(url_register,headers=headers,data=json.dumps(data))

if r.status_code!=200:
    print('something went wrong!')
    print(r.text)
    exit()

res=eval(r.text)

if not crypto.rsa_verify(eval(res['sig_id']),str(res['id']),server_pk):
    print('signature is not valud!')
    exit()

if not crypto.rsa_verify(eval(res['sig_port']),str(res['port']),server_pk):
   print('signature is not valud!')
   exit() 

r=requests.post(url=url_verify,headers=headers,data=json.dumps(data))

if r.status_code!=200:
    print('something went wrong!')
    print(r.text)
    exit()

token=input('Please enter the token sent to your email address:')

r=requests.get(url=url_email_confirm.format(token=token))

if r.status_code!=200:
    print('something went wrong!')
    print(r.text)
    exit()

print(r.text)

f=open('/home/meyvy/Documents/studies/uni/term6/cryptography/code/project/client/config.txt','w+')
f.write(user_name+'\n')
f.write(name+'\n')
f.write(email+'\n')
f.write(str(res['port'])+'\n')
f.write(str(res['id']))
