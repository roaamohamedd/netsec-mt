import json
import os
import base64
import pyotp
import requests
import hashlib

def handle_reg(username, password):
    salt = os.urandom(16) # 16 bytes of random salt

    hash_obj = hashlib.sha256(salt + password.encode())
    password_hash = hash_obj.digest()
    
    record = {
        "username": username,
        "salt": base64.b64encode(salt).decode(), # store as string,
        "pass": base64.b64encode(password_hash).decode(),
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

    hash_obj = hashlib.sha256(salt + password.encode())
    input_hash = hash_obj.digest()
    

    if password_hash == input_hash:
        print("login succ")
        return [200, "logok"]

    else:
        return [400, "err"]

def handle_otp(type, company):
    if type == "getsecret":
        try:
            username = company
            with open(f"users/{username}_vault.json", "r") as f:
                record = json.load(f)
            
            secret = record["otp_special"]

            return [200, secret]
        
        except Exception as e:
            return [400, "err"]

    elif type == "code":
        code = company

        print(f"OTP CODE: {code}")
        return [200, code]

    elif type == "verify":
        code = company[0]
        username = company[1]
        # Server URL
        url = "https://127.0.0.1:4444"

        data = f"otp:verify:{code}:{username}"

        response = requests.post(url, data=data, verify=False)
        # Print server response
        print(response.text)
        return response.text

def handle_req(body):
    if ":" not in body:
        return [400, "err"]
    
    body = body.split(":")
    
    if body[0] == "reg": # reg:username:password # register
        return handle_reg(body[1], body[2])

    elif body[0] == "log": # log:username:password # login
       return handle_log(body[1], body[2])

    elif body[0] == "otp": # otp:getsecret:username # get user's secret generated
       return handle_otp(body[1], body[2:])

    else:
        return [400, "err"]