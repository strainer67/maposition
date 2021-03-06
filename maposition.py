#!/usr/bin/env python3

from base64 import b64decode
from datetime import datetime, timedelta
import hashlib
from itertools import repeat
import logging
from logging.handlers import RotatingFileHandler
import os
import sqlite3
from urllib.parse import parse_qs

from Crypto.Cipher import AES
from Crypto import Random
from flask import Flask, redirect, render_template, request, url_for, make_response, session

app = Flask(__name__)
app.secret_key = os.urandom(16)
app.permanent_session_lifetime = timedelta(minutes=20)
app.config['server_key_db'] = os.environ.get('server_key_db')
if app.config['server_key_db'] is None or len(app.config['server_key_db']) != 32:
    app.config['server_key_db'] = 'BTk5EJhrpdLJi4urDedZbhSzjCLPUuUn'


class AESEncryption():
    """
    Encrypt and decrypt message using algorithm AES 256.
    """
    def __init__(self, encryption_key):
        self.key = encryption_key
        self.cipher_message = ""
        self.decrypted_message = ""

    def encrypt(self, message, iv):
        """
        Encrypt the string message.
        """
        message_pad = message + (16 - len(message) % 16) * chr(16 - len(message) % 16)
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        self.cipher_message = cipher.encrypt(message_pad.encode('utf-8'))

    def decrypt(self, cipher_message, iv):
        """
        Decrypt the cypher.
        """
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        decrypted_message_pad = cipher.decrypt(cipher_message).decode('utf-8')
        self.decrypted_message = AESEncryption.unpad(decrypted_message_pad)

    @staticmethod
    def unpad(message_pad):
        """
        Unpad the message
        """
        nbr_str_add = ord(message_pad[-1])
        return message_pad[:len(message_pad) - nbr_str_add]


class Content():
    def __init__(self, request):
        self.request = request
        self.valide = False
        self.utc_time = ""
        self.latitude = ""
        self.longitude = ""
        self.auth = ""
        self.username = ""
        self.password = ""

    def parse(self):
        body = parse_qs(self.request.data.decode(encoding='utf-8'))
        try:
            self.utc_time = body['time'][0]
            self.latitude = body['lat'][0]
            self.longitude = body['lon'][0]
            self.auth = self.request.headers['Authorization'].split()[1]
            self.auth = b64decode(self.auth).decode(encoding='utf-8')
            self.username, self.password = self.auth.split(':')
        except KeyError:
            pass

    def validate(self):
        try:
            self.utc_time = datetime.strptime(self.utc_time,
                                              '%Y-%m-%dT%H:%M:%S.%fZ')
            self.latitude = float(self.latitude)
            self.longitude = float(self.longitude)
            if int(abs(self.latitude)) in range(0, 90) and\
               int(abs(self.longitude)) in range(0, 180) and\
               self.username != "" and self.password != "":
                self.valide = True
        except ValueError:
            pass

    def encrypt(self, key_db, iv):
        encryption = AESEncryption(key_db)
        encryption.encrypt(str(round(self.latitude, 5)), iv)
        self.latitude = encryption.cipher_message
        encryption.encrypt(str(round(self.longitude, 5)), iv)
        self.longitude = encryption.cipher_message
        encryption.encrypt(self.utc_time.strftime('%d-%m-%Y %H:%M:%S'), iv)
        self.utc_time = encryption.cipher_message


def fill_geojson(time, latitude, longitude):
    """
    Fill a geojson file.
    """
    timestamp = datetime.strptime(time, '%d-%m-%Y %H:%M:%S').timestamp()
    id_feature = str(int(timestamp))
    my_geojson = {"type": "Feature",
                  "properties": {
                      "popupContent": f"UTC: {time}<br>latitude: {latitude}<br>longitude {longitude}",
                      "id": id_feature
                  },
                  "geometry": {
                      "type": "Point",
                      "coordinates": [longitude, latitude]
                  }
                  }
    return my_geojson


@app.route('/')
def home():
    if 'username' in session:
        return redirect(url_for("map_my_position"), code=301)
    return redirect(url_for("login"), code=301)


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'GET':
        if 'username' in session:
            return redirect(url_for("map_my_position"), code=301)
        app.logger.info('Welcome to the login page')
        return render_template('login.html')
    if request.method == 'POST':
        username_form = bytes(request.form['username'], 'utf-8')
        hash_username_form = hashlib.sha256(username_form).hexdigest()
        password_form = bytes(request.form['password'], 'utf-8')
        hash_password_form = hashlib.sha256(password_form).hexdigest()
        with sqlite3.connect('db/USERS_POSITIONS.db') as conn:
            cursor = conn.execute(f"SELECT username, password FROM users WHERE username = '{hash_username_form}' and password = '{hash_password_form}'")
        try:
            record = list(cursor)[0]
        except IndexError:
            app.logger.warning('Invalid login')
            return make_response((render_template('login.html'), 201))
        app.logger.info('Logged in successfully')
        session.permanent = True
        session['username'] = request.form['username']
        return redirect(url_for("map_my_position"), code=301)


@app.route('/logout', methods=['GET'])
def logout():
    app.logger.info('Log out successfully')
    session.pop('username', None)
    return redirect(url_for("login"), code=301)


@app.route('/get_position', methods=['GET'])
def get_position():
    if 'username' in session:
        username = bytes(session['username'], 'utf-8')
        hash_username = hashlib.sha256(username).hexdigest()
        with sqlite3.connect('db/USERS_POSITIONS.db') as conn:
            cursor = conn.execute(f"SELECT id FROM users WHERE username = '{hash_username}'")
            record = list(cursor)[0]
            user_id = record[0]
            cursor = conn.execute(f"SELECT utc_time, latitude, longitude, iv FROM positions WHERE user_id = {user_id} ORDER BY id DESC LIMIT 1")
        try:
            last_record = list(cursor)[0]
            time_crypted = last_record[0]
            latitude_crypted = last_record[1]
            longitude_crypted = last_record[2]
            username, server_key_db = session['username'], app.config['server_key_db']
            key_db = bytes(f'{username}{server_key_db}'[:32], 'utf-8')
            iv = last_record[3]
            encryption = AESEncryption(key_db)
            encryption.decrypt(time_crypted, iv)
            time = encryption.decrypted_message
            encryption.decrypt(latitude_crypted, iv)
            latitude = encryption.decrypted_message
            encryption.decrypt(longitude_crypted, iv)
            longitude = encryption.decrypted_message
        except IndexError:
            # case where there is no data yet for the user.
            time = datetime.now().strftime('%d-%m-%Y %H:%M:%S')
            latitude, longitude = 48.58392, 7.74553
        my_geojson = fill_geojson(time, latitude, longitude)
        return my_geojson
    else:
        return redirect(url_for("login"), code=301)


@app.route('/my_position', methods=['GET'])
def map_my_position():
    if 'username' in session:
        return make_response((render_template('carte.html'), 201))
    else:
        return redirect(url_for("login"), code=301)


@app.route('/send_position', methods=['POST'])
def feed_db():
    content = Content(request)
    app.logger.info('Request received by the server')
    content.parse()
    content.validate()
    if content.valide:
        app.logger.info('The content of the request is valid')
        hash_username = hashlib.sha256(bytes(content.username, 'utf-8')).hexdigest()
        hash_password = hashlib.sha256(bytes(content.password, 'utf-8')).hexdigest()
        server_key_db = app.config['server_key_db']
        key_db = bytes(f'{content.username}{server_key_db}'[:32], 'utf-8')
        iv = Random.get_random_bytes(16)
        content.encrypt(key_db, iv)
        with sqlite3.connect('db/USERS_POSITIONS.db') as conn:
            cursor = conn.execute(f"SELECT id FROM users where username = '{hash_username}' and password = '{hash_password}'")
            try:
                record = list(cursor)[0]
                user_id = record[0]
                sql_insertion = """INSERT INTO positions(utc_time, latitude, longitude, iv, user_id) VALUES(?,?,?,?,?)"""
                data = (content.utc_time, content.latitude, content.longitude,
                        iv, user_id)
                conn.execute(sql_insertion, data)
            except IndexError:
                app.logger.info('an unauthorized person tries to feed the database')
                return make_response((render_template('unauthorized.html'), 401))
        return make_response(('Position updated', 200))
    else:
        app.logger.info('The content of the request is invalid')
        return make_response((render_template('badrequest.html'), 400))


if __name__ == "__main__":
    file_handler = RotatingFileHandler('logs/app.log', 'a', 1024*1024, 1)
    formatter = logging.Formatter('%(asctime)s :: %(levelname)s :: %(message)s')
    file_handler.setFormatter(formatter)
    file_handler.setLevel(logging.INFO)
    app.logger.addHandler(file_handler)
    app.logger.setLevel(logging.INFO)
    app.run()
