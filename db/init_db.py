#!/usr/bin/python3

import argparse
import sqlite3


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Create a database \
                                     with two tables: users and positions.')
    args = parser.parse_args() 
    with sqlite3.connect('USERS_POSITIONS.db') as conn:
        cur = conn.cursor()
        cur.execute('CREATE TABLE users(id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT UNIQUE, password TEXT)')
        cur.execute('CREATE TABLE positions(id INTEGER PRIMARY KEY AUTOINCREMENT, utc_time TEXT, latitude REAL, longitude REAL, user_id INTEGER)')
