#!/usr/bin/env python3

from base64 import b64decode
from datetime import datetime, timedelta
import hashlib
from itertools import cycle
import json
import logging
from logging.handlers import RotatingFileHandler
from math import isclose
import os
import sqlite3

from flask import Flask, redirect, render_template, request, url_for, make_response, session

app = Flask(__name__)
app.secret_key = os.urandom(12)
app.permanent_session_lifetime = timedelta(minutes=10)


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
        try:
            self.utc_time = self.request.args.get('time')
            self.latitude = self.request.args.get('lat')
            self.longitude = self.request.args.get('lon')
        except IndexError:
            pass
        try:
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

    def customize(self):
        self.latitude = round(self.latitude, 5)
        self.longitude = round(self.longitude, 5)
        self.utc_time = self.utc_time.strftime('%d-%m-%Y %H:%M:%S')


def fill_geojson(time, latitude, longitude):
    """
    Fill a geojson file.
    """
    timestamp = datetime.strptime(time, '%d-%m-%Y %H:%M:%S').timestamp()
    id_feature = str(int(timestamp))
    my_geojson = {"type": "Feature",
                  "properties": {
                      "popupContent": f"UTC: {time} latitude: {latitude} longitude {longitude}",
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
        return redirect(url_for("map_my_position"), code=302)
    return redirect(url_for("login"), code=302)


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'GET':
        if 'username' in session:
            return redirect(url_for("map_my_position"), code=302)
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
        return redirect(url_for("map_my_position"), code=302)


@app.route('/logout', methods=['GET'])
def logout():
    app.logger.info('Log out successfully')
    session.pop('username', None)
    return redirect(url_for("login"), code=302)


@app.route('/get_position', methods=['GET'])
def get_position():
    if 'username' in session:
        username = bytes(session['username'], 'utf-8')
        hash_username = hashlib.sha256(username).hexdigest()
        with sqlite3.connect('db/USERS_POSITIONS.db') as conn:
            cursor = conn.execute(f"SELECT id FROM users WHERE username = '{hash_username}'")
            record = list(cursor)[0]
            user_id = record[0]
            cursor = conn.execute(f"SELECT utc_time, latitude, longitude FROM positions WHERE user_id = {user_id} ORDER BY id DESC LIMIT 1")
        try:
            last_record = list(cursor)[0]
            time, latitude, longitude = last_record[0], last_record[1], last_record[2]
        except IndexError:
            # case where there is no data yet for the user.
            time = datetime.now().strftime('%d-%m-%Y %H:%M:%S')
            latitude, longitude = 48.58392, 7.74553
        my_geojson = fill_geojson(time, latitude, longitude)
        return my_geojson
    else:
        return redirect(url_for("login"), code=302)


@app.route('/my_position', methods=['GET'])
def map_my_position():
    if 'username' in session:
        return make_response((render_template('carte.html'), 201))
    else:
        return redirect(url_for("login"), code=302)


@app.route('/send_position', methods=['GET'])
def feed_db():
    content = Content(request)
    app.logger.info('Request received by the server')
    content.parse()
    content.validate()
    if content.valide:
        app.logger.info('The content of the request is valid')
        hash_username = hashlib.sha256(bytes(content.username, 'utf-8')).hexdigest()
        hash_password = hashlib.sha256(bytes(content.password, 'utf-8')).hexdigest()
        content.customize()
        with sqlite3.connect('db/USERS_POSITIONS.db') as conn:
            cursor = conn.execute(f"SELECT id FROM users where username = '{hash_username}' and password = '{hash_password}'")
            try:
                record = list(cursor)[0]
                user_id = record[0]
                conn.execute(f"INSERT INTO positions(utc_time, latitude, longitude, user_id) VALUES('{content.utc_time}', {content.latitude}, {content.longitude}, {user_id})")
            except IndexError:
                app.logger.info('an unauthorized person tries to feed the database')
                return make_response((render_template('unauthorized.html'), 401))
        return make_response((request.query_string, 200))
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
