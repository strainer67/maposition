#!/usr/bin/python3
from itertools import cycle
import requests
import random
from datetime import datetime
import time


if __name__ == "__main__":
    url_base = 'http://127.0.0.1:5000/send_position?'
    user_id = 1
    while True:
        my_lat = round(random.uniform(48.55392, 48.61392), 5)
        my_lon = round(random.uniform(7.71553, 7.775530), 5)
        my_time = datetime.now().strftime('%d-%m-%Y %H:%M:%S')
        content = f'lat={my_lat}&lon={my_lon}&time={my_time}&user_id={user_id}'
        data = f'{url_base}{content}'
        r = requests.get(data)
        print(content)
        time.sleep(20)
