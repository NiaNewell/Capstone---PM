import json, base64, string
import getpass, os, secrets
from auth.session import session
from auth.slots import rewrite_slots
from crypto.crypto_utils import generate_vk, derive_kek, unwrap
from cryptography.fernet import Fernet
from config import MASTER_JSON
from datetime import datetime, timezone
from vault.vault import save_vault
from USB.usb_installer import wrap_store_secret, read_unwrap_secret

#Master Password Set-up
def setup_master_password():
    pw1 = get_confirm_pass()
    pin = get_confirm_pin()

    vault_key = generate_vk()
    usb_secret = os.urandom(32)

    # Writes pm_install.key to USB drive
    if not wrap_store_secret(usb_secret, pin):
        print("Setup failed: USB not found.")
        return False

    recovery_key = secrets.token_hex(16)
    created = datetime.now(timezone.utc).isoformat()
    rewrite_slots(vault_key, pw1, usb_secret, recovery_key, created)

    fernet = Fernet(base64.urlsafe_b64encode(vault_key))
    save_vault({"groups": {}}, fernet)

    return (recovery_key)


def login():
    usb_secret = read_unwrap_secret()
    if usb_secret is None:
        return None

    master = json.load(open(MASTER_JSON))
    slot = master["slots"]["normal"]

    for attempt in range(3):
        pw = getpass.getpass("Enter master password: ")

        if verify_master_password(pw, usb_secret):

            salt = base64.b64decode(slot["salt"])
            kdf = master["kdf"]
            kek = derive_kek(pw.encode(), usb_secret, salt, kdf["n"], kdf["r"], kdf["p"])

            vault_key = unwrap(kek, base64.b64decode(slot["wrapped_key"]), slot["aad"])

            session.start(vault_key, usb_secret)

            return Fernet(base64.urlsafe_b64encode(vault_key))
        
        print("Authentication failed.")

    return None


def verify_master_password(master_password, usb_secret):

    master = json.load(open(MASTER_JSON))
    slot = master["slots"]["normal"]
    salt = base64.b64decode(slot["salt"])
    kdf = master["kdf"]

    kek = derive_kek(master_password.encode(), usb_secret, salt, kdf["n"], kdf["r"], kdf["p"])

    try:
        unwrap(kek, base64.b64decode(slot["wrapped_key"]), slot["aad"])
        return True
    
    except Exception:
        return False

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


def get_confirm_pass():
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
        
        return pw1

def get_confirm_pin():
    while True: 
        pin = getpass.getpass("Create USB PIN: ")

        if not pin.isdigit() or len(pin) < 6:
            print("PIN must be at least 6 digits.")
            continue

        pin2 = getpass.getpass("Confirm USB PIN: ")
        if pin != pin2:
            print("PINs do not match.")
            continue

        return pin