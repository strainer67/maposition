#!/usr/bin/python3

import argparse
import hashlib
import sqlite3


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Remove an user and its recording in the database.')
    parser.add_argument('username', help='username of the user')
    args = parser.parse_args()
    username = args.username
    hash_username = hashlib.sha256(bytes(username, 'utf-8')).hexdigest()
    with sqlite3.connect('USERS_POSITIONS.db') as conn:
        cur = conn.cursor()
        cur.execute(f"SELECT id FROM users where username='{hash_username}'")
        user_id = list(cur)[0][0]
        cur.execute(f"DELETE FROM users WHERE id={user_id}")
        cur.execute(f"DELETE FROM positions WHERE user_id={user_id}")

