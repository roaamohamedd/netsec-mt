# auth_client.py
import requests

SERVER_URL = "https://127.0.0.1:4443"
VERIFY_CERT = False   # set to server cert if available

def client_register(username: str, password: str) -> bool:
    body = f"reg:{username}:{password}"
    try:
        r = requests.post(SERVER_URL, data=body, verify=VERIFY_CERT)
        if r.status_code == 200 and "regok" in r.text:
            print("[+] Registration successful")
            return True
        print("[!] Registration failed:", r.text)
        return False
    except Exception as e:
        print("Registration error:", e)
        return False


def client_login(username: str, password: str) -> bool:
    body = f"log:{username}:{password}"
    try:
        r = requests.post(SERVER_URL, data=body, verify=VERIFY_CERT)
        if r.status_code == 200 and "logok" in r.text:
            print("[+] Login successful")
            return True
        print("[!] Login failed:", r.text)
        return False
    except Exception as e:
        print("Login error:", e)
        return False
