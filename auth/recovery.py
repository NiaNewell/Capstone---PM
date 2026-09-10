import json, base64, secrets, getpass, os
from datetime import datetime, timezone
from auth.slots import rewrite_slots
from auth.auth import get_confirm_pass, get_confirm_pin
from crypto.crypto_utils import unwrap, derive_kek
from config import MASTER_JSON
from USB.usb_installer import read_unwrap_secret, wrap_store_secret


def now_iso():
    return datetime.now(timezone.utc).isoformat()


def recover_masterpass():
    usb_secret = read_unwrap_secret()
    if usb_secret is None:
        return None
    
    recovery_key = input("Enter recovery key: ").strip()

    master = json.load(open(MASTER_JSON))
    slot = master["slots"]["lost_password"]
    salt = base64.b64decode(slot["salt"])

    kdf = master["kdf"]
    kek = derive_kek(recovery_key.encode(), usb_secret, salt, kdf["n"], kdf["r"], kdf["p"] )

    try:
        vault_key = unwrap(kek, base64.b64decode(slot["wrapped_key"]), slot["aad"])
    except Exception:
        print("Recovery failed.")
        return None


    new_pass = get_confirm_pass()
    new_rk = secrets.token_hex(16)

    rewrite_slots(vault_key, new_pass, usb_secret, new_rk, now_iso())
    return vault_key, usb_secret, new_rk


def recover_lost_usb():
    master_pass = getpass.getpass("Enter master password: ")
    recovery_key = input("Enter recovery key: ").strip()

    master = json.load(open(MASTER_JSON))
    slot = master["slots"]["lost_usb"]
    salt = base64.b64decode(slot["salt"])

    kdf = master["kdf"]
    kek = derive_kek(recovery_key.encode(), master_pass.encode(), salt, kdf["n"], kdf["r"], kdf["p"])


    try:
        vault_key = unwrap(kek, base64.b64decode(slot["wrapped_key"]), slot["aad"])
    except Exception:
        print("Recovery failed.")
        return None

    new_usb_secret = os.urandom(32)
    new_pin = get_confirm_pin()
    if not wrap_store_secret(new_usb_secret, new_pin):
        print("Failed to install new USB secret.")
        return None

    new_rk = secrets.token_hex(16)
    created = datetime.now(timezone.utc).isoformat()


    rewrite_slots(vault_key, master_pass, new_usb_secret, new_rk, created)
    return vault_key, new_usb_secret, new_rk