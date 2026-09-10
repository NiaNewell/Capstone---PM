import os
import base64
import getpass
from crypto.crypto_utils import derive_kek, wrap, unwrap, write_json
from USB.usb_auth import find_file_usb
import json


n, r, p = 2**17, 8, 1
AAD = "usb-secret:v2"

def wrap_store_secret(secret: bytes, pin: str):
    usb_path, _ = find_file_usb()
    if not usb_path:
        print("USB not found.")
        return False

    salt = os.urandom(16)
    kek = derive_kek(pin.encode(), b"", salt, n, r, p)
    blob = wrap(kek, secret, AAD)

    record = {
        "version": 2,
        "kdf": {"name": "scrypt", "n": n, "r": r, "p": p},
        "salt": base64.b64encode(salt).decode(),
        "wrapped_secret": base64.b64encode(blob).decode(),
        "aad": AAD,
    }
    write_json(usb_path, record)
    return True

def read_unwrap_secret():
    usb_path, _ = find_file_usb()
    if not usb_path:
        print("USB not found.")
        return None

    record = json.load(open(usb_path))
    salt = base64.b64decode(record["salt"])
    kdf = record["kdf"]

    for attempt in range(3):
        pin = getpass.getpass("Enter USB PIN: ")
        kek = derive_kek(pin.encode(), b"", salt, kdf["n"], kdf["r"], kdf["p"])
        try:
            return unwrap(kek, base64.b64decode(record["wrapped_secret"]), record["aad"])
        except Exception:
            print("Incorrect PIN.")

    print("Too many failed attempts.")
    return None

