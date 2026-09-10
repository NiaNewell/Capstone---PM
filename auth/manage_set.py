import secrets, getpass
from datetime import datetime, timezone
from cryptography.fernet import Fernet
from USB.usb_installer import wrap_store_secret
from auth.auth import get_confirm_pin, get_confirm_pass, verify_master_password
from auth.session import session
from auth.slots import rewrite_slots

def change_masterpass():
    vault_key = session.vault_key
    usb_secret = session.usb_secret

    if vault_key is None or usb_secret is None:
        return False

    # Re-authenticate before changing Master Password
    for attempt in range(3):
        current_password = getpass.getpass("Enter current master password: ")

        if verify_master_password(current_password, usb_secret):
            break

        print("Authentication failed.")

        if attempt == 2:
            print("Too many failed attempts.")
            return False

    new_password = get_confirm_pass()

    new_rk = secrets.token_hex(16)
    created = datetime.now(timezone.utc).isoformat()

    rewrite_slots(vault_key, new_password, usb_secret, new_rk, created)
    
    return new_rk


def change_usb_pin():
    vault_key = session.vault_key
    usb_secret = session.usb_secret

    if vault_key is None or usb_secret is None:
        return False

    # Re-authenticate before changing PIN
    for attempt in range(3):
        masterpass = getpass.getpass("Enter current master password: ")

        if verify_master_password(masterpass, usb_secret):
            break

        print("Authentication failed.")

        if attempt == 2:
            print("Too many failed attempts.")
            return False

    new_pin = get_confirm_pin()
   
    if not wrap_store_secret(usb_secret, new_pin):
        print("Failed to update USB PIN.")
        return False

    new_rk = secrets.token_hex(16)
    created = datetime.now(timezone.utc).isoformat()

    rewrite_slots(vault_key, masterpass, usb_secret, new_rk, created)
    
    return new_rk

