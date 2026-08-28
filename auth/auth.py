import json, hmac, base64, string
import getpass
import os
from auth.session import session
from USB.usb_auth import find_file_usb
from crypto.crypto_utils import derive_fernet_key
from cryptography.fernet import Fernet
from config import MASTER_JSON, VAULT_FILE
import time

#Master Password Set-up
def setup_master_password():
    print("=== First-Time Setup ===")

    while True:
        pw1 = getpass.getpass("Create master password: ")
        pw2 = getpass.getpass("Confirm master password: ")

        error = validate_pass(pw1)

        if error:
            print(error)
            continue

        if pw1 != pw2:
            print("Passwords do not match.")
            continue

        break

    # Locates USB secret file and pulls path
    usb_path, _ = find_file_usb()

    if not usb_path:
        print("USB secret file not found.")
        return False

    with open(usb_path, "r", encoding="utf-8") as f:
        usb_secret = f.read().strip()

    # Scrypt parameters
    n, r, p = 2**14, 8, 1
    salt = os.urandom(16)

    # Derive encryption key (using master pass, USB data, salt and kdf param)
    fkey = derive_fernet_key(pw1, usb_secret, salt, n, r, p)
    
    #Data to be stored in json file
    master_record = {
        "kdf": {"n": n, "r": r, "p": p},
        "salt": base64.b64encode(salt).decode(),
        "verifier": fkey.decode()
    }

    with open(MASTER_JSON, "w") as f:
        json.dump(master_record, f, indent=2)

    # Initialize encrypted vault
    vault = Fernet(fkey).encrypt(json.dumps({"groups": {}}).encode())

    with open(VAULT_FILE, "wb") as f:
        f.write(vault)

    print("Master password set.")
    return True


def login():
    fernet = verify_masterpass()

    if not fernet:
        return False

    print("Access granted.")
    session.authenticated = True
    session.login_time = time.time()
    session.auth_method = "usb+master_password"

    return fernet 




def validate_pass(password):
    if len(password) < 8:
        return "Password must be at least 8 characters long."

    if not any(c.isupper() for c in password):
        return "Password must contain at least one uppercase letter."

    if not any(c.islower() for c in password):
        return "Password must contain at least one lowercase letter."

    if not any(c.isdigit() for c in password):
        return "Password must contain at least one number."

    if not any(c in string.punctuation for c in password):
        return "Password must contain at least one special character."

    return None


def verify_masterpass():
    try:
        with open(MASTER_JSON, "r") as f:
            master = json.load(f)

    except FileNotFoundError:
        print("Missing or corrupted master.json")
        return None
    
    except json.JSONDecodeError:
        print("master.json is corrupted.")
        return None
    
    except Exception as e:
        print(f"Unexpected error: {e}")
        return None

    kdf = master["kdf"]
    n, r, p = kdf["n"], kdf["r"], kdf["p"]

    salt = base64.b64decode(master["salt"])
    stored_verifier = master["verifier"].encode()

    # Locate USB secret file
    usb_path, _ = find_file_usb()

    if not usb_path:
        print("USB not found.")
        return None

    with open(usb_path, "r", encoding="utf-8") as f:
        usb_secret = f.read().strip()

    # Allow up to 3 password attempts
    for attempt in range(3):
        
        pw = getpass.getpass("Enter master password: ")
        
        key = derive_fernet_key(pw, usb_secret, salt, n, r, p)

    # Checks if derived key matches stored key before session authentication
        if hmac.compare_digest(key, stored_verifier):
            return Fernet(key)

        print("Incorrect Master Password.")

    print("Too many incorrect password attempts. Access Denied.")
    return False  

    