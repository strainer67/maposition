#!/usr/bin/python3

import argparse
import hashlib
import sqlite3


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Add an user in the database.')
    parser.add_argument('username', help='username of the user')
    parser.add_argument('password', help='password of the user')
    args = parser.parse_args()
    username = args.username
    password = args.password
    hash_username = hashlib.sha256(bytes(username, 'utf-8')).hexdigest()
    hash_password = hashlib.sha256(bytes(password, 'utf-8')).hexdigest()
    with sqlite3.connect('USERS_POSITIONS.db') as conn:
        cur = conn.cursor()
        cur.execute(f"INSERT INTO users(username, password) VALUES('{hash_username}', '{hash_password}')")