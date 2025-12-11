from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import json
import os
from cryptography.hazmat.primitives import hashes
import base64
import pyotp

def handle_reg(username, password):
    salt = os.urandom(16) # 16 bytes of random salt

    kdf = PBKDF2HMAC( # key/hash generated from password
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )
    
    key_hash = kdf.derive(password.encode())

    record = {
        "username": username,
        "salt": base64.b64encode(salt).decode(), # store as string,
        "pass": base64.b64encode(key_hash).decode(),
        "otp_special": pyotp.random_base32()
    }

    with open(f"users/{username}_vault.json", "w") as f:
        json.dump(record, f, indent=4)

    return [200, "regok"]

def handle_log(username, password):
    with open(f"users/{username}_vault.json", "r") as f:
        record = json.load(f)

    # Decode salt and stored hash
    salt = base64.b64decode(record["salt"])
    password_hash = base64.b64decode(record["pass"])

    # Derive key from input password
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000
    )
    try:
        kdf.verify(password.encode(), password_hash) # compare
        return [200, "logok"]
    except Exception:
        return [400, "err"]

def handle_otp(type, username):
    if(type == "getsecret"):
        try:
            with open(f"users/{username}_vault.json", "r") as f:
                record = json.load(f)
            
            secret = record["otp_special"]

            # Return the otp secret so the mobile app can compute/verify TOTP
            return [200, secret]
        
        except:
            return [400, "err"]


def handle_req(body):
    if ":" not in body:
        return [400, "err"]
    
    body = body.split(":")
    
    if body[0] == "reg": # reg:username:password # register
        return handle_reg(body[1], body[2])

    elif body[0] == "log": # log:username:password # login
       return handle_log(body[1], body[2])

    elif body[0] == "otp": # otp:getsecret:username # get user's secret generated
       return handle_otp(body[1], body[2])

    else:
        return [400, "err"]