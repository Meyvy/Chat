import mysql.connector
from project import crypto
import socket
from contextlib import closing


class Error(Exception):
    pass


def check_socket():
    host = '127.0.0.1'
    ports = []
    for i in range(1, 65536):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        if sock.connect_ex((host, i)) == 0:
            ports.append(i)
        sock.close()
    return ports


USER = ''
PASSWORD = ''
HOST = ''
DATABASE = ''


cnx = mysql.connector.connect(
    user=USER, password=PASSWORD, host=HOST, database=DATABASE)


def user_name_exists(user_name):
    cnx = mysql.connector.connect(
        user=USER, password=PASSWORD, host=HOST, database=DATABASE)
    cursor = cnx.cursor()
    query = '''SELECT * FROM user WHERE user_name='{user_name}' '''.format(
        user_name=user_name)
    cursor.execute(query)
    res = cursor.fetchone()
    cnx.close()
    return res != None


def port_exists(port):
    cnx = mysql.connector.connect(
        user=USER, password=PASSWORD, host=HOST, database=DATABASE)
    cursor = cnx.cursor()
    query = 'SELECT * FROM user WHERE port_number={port}'.format(port=port)
    cursor.execute(query)
    res = cursor.fetchone()
    cnx.close()
    return res != None


def email_exists(email):
    cnx = mysql.connector.connect(
        user=USER, password=PASSWORD, host=HOST, database=DATABASE)
    cursor = cnx.cursor()
    query = '''SELECT * FROM user WHERE email='{email}' '''.format(email=email)
    cursor.execute(query)
    res = cursor.fetchone()
    cnx.close()
    return res != None


def get_user(user_name):
    if not user_name_exists(user_name):
        raise Error('User does not exists!')
    cnx = mysql.connector.connect(
        user=USER, password=PASSWORD, host=HOST, database=DATABASE)
    cursor = cnx.cursor()
    query = '''SELECT * FROM user WHERE user_name= '{user_name}' '''.format(
        user_name=user_name)
    cursor.execute(query)
    res = cursor.fetchone()
    cnx.close()
    return res


def validate(email):
    cnx = mysql.connector.connect(
        user=USER, password=PASSWORD, host=HOST, database=DATABASE)
    cursor = cnx.cursor()
    if not email_exists(email):
        raise Error('User does not exist')
    query = '''UPDATE user SET verified=1 WHERE email= '{email}' '''.format(
        email=email)
    print(query)
    cursor.execute(query)
    cnx.commit()
    cnx.close()


def verified(user_name):
    if not user_name_exists(user_name):
        raise Error('User does not exists!')
    cnx = mysql.connector.connect(
        user=USER, password=PASSWORD, host=HOST, database=DATABASE)
    cursor = cnx.cursor()
    query = '''SELECT * FROM user WHERE user_name='{user_name}' '''.format(
        user_name=user_name)
    cursor.execute(query)
    res = cursor.fetchone()
    print(res)
    return res[7] == 1


def insert_user(user_name, name, email, public_key):
    cnx = mysql.connector.connect(
        user=USER, password=PASSWORD, host=HOST, database=DATABASE)
    cursor = cnx.cursor()
    available_ports = check_socket()
    pk = public_key[1:]
    query = None
    for i in available_ports:
        if not port_exists(i):
            query = '''INSERT INTO user (user_name,name,email,public_key,port_number)
                VALUES('{user_name}','{name}','{email}',{pk},{port})'''.format(user_name=user_name,
                                                                               name=name, email=email, pk=pk, port=i)
            port=i
            break
    cursor.execute(query)
    inserted_id=cursor.lastrowid
    cnx.commit()
    cnx.close()
    return inserted_id,port
