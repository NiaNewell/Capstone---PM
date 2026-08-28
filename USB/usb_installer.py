import os
import base64, hmac
import getpass
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.backends import default_backend
from USB.usb_auth import find_file_usb
import json

def derive_usb_hash(usb_secret, pin, salt):

    kdf = Scrypt(
        salt=salt,
        length=32,
        n=2**14,
        r=8,
        p=1,
        backend=default_backend() )

    return kdf.derive((usb_secret + pin).encode())

def register_install_usb():

    if os.path.exists("install_usb.hash"):
        print("USB installation already registered.")
        return True

    usb_path, _ = find_file_usb()
    
    if not usb_path:
        print("Installation USB not detected.")
        return False

    with open(usb_path, "r", encoding="utf-8") as f:
        usb_secret = f.read().strip()

    if len(usb_secret) < 32:
        print("Invalid USB key.")
        return False
    
    # Ask user to create PIN
    while True:
        pin = getpass.getpass("Create USB PIN: ")

        if not pin.isdigit() or len(pin) < 4:
            print("PIN must be at least 4 digits.")
            continue

        confirm = getpass.getpass("Confirm USB PIN: ")

        if pin != confirm:
            print("PINs do not match.")
            continue

        break
    
    salt = os.urandom(16)

    derived = derive_usb_hash(usb_secret, pin, salt)

    record = {
        "salt": base64.b64encode(salt).decode(),
        "hash": base64.b64encode(derived).decode()
    }

    with open("install_usb.hash", "w") as f:
        json.dump(record, f, indent=2)

    print("USB installation complete.")
    return True

def validate_usb():

    if not os.path.exists("install_usb.hash"):
        print("USB not registered.")
        return False

    with open("install_usb.hash", "r", encoding="utf-8") as f:
        record = json.load(f)

    salt = base64.b64decode(record["salt"])
    stored_hash = base64.b64decode(record["hash"])

    usb_path, _ = find_file_usb()

    if not usb_path:
        print("USB not detected.")
        return False

    with open(usb_path, "r", encoding="utf-8") as f:
        usb_secret = f.read().strip()
        if len(usb_secret) < 32:
            print("Invalid USB key.")
            return False

    for attempt in range(3):

        pin = getpass.getpass("Enter USB PIN: ")

        derived = derive_usb_hash(usb_secret, pin, salt)

        if hmac.compare_digest(derived, stored_hash):
            print("USB authentication successful.")
            return True

        print("Incorrect PIN.")

    print("Too many failed attempts. Exiting.")
    return False

if __name__ == "__main__":
    register_install_usb()