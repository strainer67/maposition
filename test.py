#!/usr/bin/python3
from itertools import cycle
import requests
import random
from datetime import datetime
import time


if __name__ == "__main__":
    url_base = 'http://127.0.0.1:5000/send_position?'
    username = 'admin'
    password = 'password'
    while True:
        my_lat = round(random.uniform(48.55392, 48.61392), 8)
        my_lon = round(random.uniform(7.71553, 7.775530), 8)
        my_time = datetime.now().strftime('%Y-%m-%dT%H:%M:%S.%fZ')
        content = f'lat={my_lat}&lon={my_lon}&time={my_time}'
        print(content)
        data = f'{url_base}{content}'
        r = requests.get(data, auth=(username, password))
        print(r.status_code)
        time.sleep(20)
