#!/usr/bin/env python3
"""
Simple Authentication Mobile App (CLI) for VaultGuard

Features:
- Register a user device with the MFA server
- Authenticate (verify master password) with the MFA server
- Fetch the user's OTP secret and display the current TOTP (60s window)

Notes:
- The server is expected at https://127.0.0.1:4443 by default and to
  return responses with the form used by the project's `main_server.py` (HTTP
  status set to integer and body prefixed with "res:").
- The app verifies the server TLS certificate using `cert.pem` by default.
"""
import argparse
import getpass
import json
import os
import sys
import time
import uuid

import pyotp
import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning

# Suppress warnings when verify=False is used
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)


DEFAULT_SERVER = "https://127.0.0.1:4443"
DEFAULT_CA = "cert.pem"
USERS_DIR = "users"


def send_post(body: str, server: str, ca_file: str):
    url = server
    try:
        # Handle TLS verification based on ca_file parameter
        if ca_file is False:
            # Disable verification (for self-signed certs in testing)
            verify_cert = False
        else:
            # Use the provided CA file path or system certs
            verify_cert = ca_file if isinstance(ca_file, str) else True
        
        r = requests.post(url, data=body.encode(), verify=verify_cert, timeout=5)
    except requests.exceptions.SSLError as e:
        print("TLS verification failed:", e)
        return None, None
    except requests.exceptions.ConnectionError as e:
        print("Connection error:", e)
        return None, None
    except Exception as e:
        print("Request failed:", e)
        return None, None

    # Server writes responses like: b"res:" + str(res[1]).encode()
    text = r.text
    if text.startswith("res:"):
        payload = text[len("res:"):]
    else:
        payload = text

    return r.status_code, payload


def save_device_record(username: str, device_id: str, server: str, ca_file: str):
    os.makedirs(USERS_DIR, exist_ok=True)
    path = os.path.join(USERS_DIR, f"mobile_{username}.json")
    rec = {"device_id": device_id, "server": server, "ca_file": ca_file}
    with open(path, "w") as f:
        json.dump(rec, f, indent=2)
    print(f"Saved device record to {path}")


def load_device_record(username: str):
    path = os.path.join(USERS_DIR, f"mobile_{username}.json")
    if not os.path.exists(path):
        return None
    with open(path, "r") as f:
        return json.load(f)


def cmd_register(args):
    username = args.username
    password = args.password or getpass.getpass("Master Password: ")
    server = args.server
    ca_file = args.ca

    body = f"reg:{username}:{password}"
    status, payload = send_post(body, server, ca_file)
    if status == 200 and payload and payload.lower().startswith("regok"):
        device_id = str(uuid.uuid4())
        save_device_record(username, device_id, server, ca_file)
        print("Registration succeeded.")
    else:
        print("Registration failed. Server returned:", status, payload)


def cmd_login(args):
    username = args.username
    password = args.password or getpass.getpass("Master Password: ")
    server = args.server
    ca_file = args.ca

    body = f"log:{username}:{password}"
    status, payload = send_post(body, server, ca_file)
    if status == 200 and payload and payload.lower().startswith("logok"):
        print("Master password verified by server.")
        # Try to fetch secret and display OTP
        secret = fetch_secret(username, server, ca_file)
        if secret:
            show_totp(secret)
        else:
            print("Could not retrieve OTP secret from server.")
    else:
        print("Login failed. Server returned:", status, payload)


def fetch_secret(username: str, server: str, ca_file: str):
    body = f"otp:getsecret:{username}"
    status, payload = send_post(body, server, ca_file)
    if status == 200 and payload:
        # Expect payload to be the base32 secret string
        return payload.strip().strip('"')
    else:
        return None


def show_totp(secret: str):
    try:
        totp = pyotp.TOTP(secret, interval=60)
    except Exception as e:
        print("Invalid OTP secret:", e)
        return

    otp = totp.now()
    # compute seconds left in 60-second window
    interval = 60
    now = int(time.time())
    elapsed = now % interval
    left = interval - elapsed
    print(f"Current OTP (valid {left}s): {otp}")


def cmd_getotp(args):
    username = args.username
    server = args.server
    ca_file = args.ca
    secret = fetch_secret(username, server, ca_file)
    if not secret:
        print("Failed to fetch OTP secret from server.")
        return
    show_totp(secret)


def build_parser():
    p = argparse.ArgumentParser(prog="mobile_app.py", description="VaultGuard Authentication Mobile App (CLI)")
    p.add_argument("--server", default=DEFAULT_SERVER, help="MFA server URL (https) - default: %(default)s")
    p.add_argument("--ca", default=DEFAULT_CA, help="Path to CA / server cert to verify TLS - default: %(default)s")

    sub = p.add_subparsers(dest="cmd")

    reg = sub.add_parser("register", help="Register a user and this mobile device with the MFA server")
    reg.add_argument("username")
    reg.add_argument("--password", help="Master password (if omitted, will prompt)")
    reg.set_defaults(func=cmd_register)

    log = sub.add_parser("login", help="Verify master password with server and show current OTP")
    log.add_argument("username")
    log.add_argument("--password", help="Master password (if omitted, will prompt)")
    log.set_defaults(func=cmd_login)

    geto = sub.add_parser("get-otp", help="Fetch the OTP secret from the server and display current TOTP")
    geto.add_argument("username")
    geto.set_defaults(func=cmd_getotp)

    return p


def main(argv=None):
    p = build_parser()

    if argv is None:
        argv = sys.argv[1:]

    # Pre-parse global options so they can appear anywhere
    global_parser = argparse.ArgumentParser(add_help=False)
    global_parser.add_argument("--server", default=DEFAULT_SERVER)
    global_parser.add_argument("--ca", default=DEFAULT_CA)
    known, remaining = global_parser.parse_known_args(argv)

    # Parse the remaining args (subcommand + its args)
    args = p.parse_args(remaining)

    # Fill in global options (prefer values from full parse if present, else use pre-parsed)
    if not hasattr(args, "server"):
        args.server = known.server
    elif args.server is None or args.server == DEFAULT_SERVER:
        args.server = known.server if known.server != DEFAULT_SERVER else args.server
    
    if not hasattr(args, "ca"):
        args.ca = known.ca
    elif args.ca is None or args.ca == DEFAULT_CA:
        args.ca = known.ca if known.ca != DEFAULT_CA else args.ca

    # Allow passing --ca False to disable TLS verification (case-insensitive)
    if hasattr(args, "ca") and isinstance(args.ca, str) and args.ca.lower() == "false":
        args.ca = False

    if not hasattr(args, "func"):
        p.print_help()
        return 1
    args.func(args)
    return 0


if __name__ == "__main__":
    sys.exit(main())
