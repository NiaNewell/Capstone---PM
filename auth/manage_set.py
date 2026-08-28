import getpass, base64, json, os, hmac
import secrets, time
from cryptography.fernet import Fernet
from USB.usb_auth import find_file_usb
from USB.usb_installer import derive_usb_hash
from auth.auth import validate_pass, verify_masterpass
from auth.session import session
from crypto.crypto_utils import derive_fernet_key, derive_recovery_verifier
from config import MASTER_JSON
from vault.vault import load_vault, save_vault

def change_masterpass():
    try:
        with open(MASTER_JSON, "r") as f:
            master = json.load(f)
    except Exception as e:
        print(f"Unexpected error: {e}")
        return None
    
    
    print("=== Update Master Password ===\n\n")

    for i in range(3):
        pw1 = getpass.getpass("Enter current master password: ")
        
        usb_path, _ = find_file_usb()

        if not usb_path:
            print("USB not found.")
            return False

        try:
            with open(usb_path, "r", encoding="utf-8") as f:
                usb_secret = f.read().strip()
        except OSError:
            print("Unable to read USB key.")
            return False

        kdf = master["kdf"]
        n, r, p = kdf["n"], kdf["r"], kdf["p"]

        salt = base64.b64decode(master["salt"])
        stored_verifier = master["verifier"].encode()

        key = derive_fernet_key(pw1, usb_secret, salt, n, r, p)

        if not hmac.compare_digest(key, stored_verifier):
            print("Incorrect password. \n")
            continue

        old_fernet = Fernet(key)
        vault_data = load_vault(old_fernet)

        if vault_data is None:
            print("Failed to load vault.")
            return False
        
        while True:
            pw2 = getpass.getpass("Enter New Master Password: \n")
            pw3 = getpass.getpass("Re-enter New Master Password: \n")

            error = validate_pass(pw2)

            if error:
                print(error)
                continue

            if pw2 != pw3:
                print("Passwords do not match.")
                continue
            break


        # Prevent reusing current master password
        old_key = derive_fernet_key(pw2, usb_secret, salt, n, r, p)

        if hmac.compare_digest(old_key, stored_verifier):
            print("New password must be different from the current password.")
            continue

        
        new_salt = os.urandom(16)
        new_key = derive_fernet_key(pw2, usb_secret, new_salt, n, r, p)

        new_fernet = Fernet(new_key)
        save_vault(vault_data, new_fernet)

        master["salt"] = base64.b64encode(new_salt).decode()
        master["verifier"] = new_key.decode()

        with open(MASTER_JSON, "w") as f:
            json.dump(master, f, indent=2)

        print("Master password updated successfully.")
        pw1 = None
        pw2 = None
        pw3 = None
        usb_secret = None
        return True


    print("Too many failed attempts.")
    pw1 = None
    pw2 = None
    pw3 = None
    usb_secret = None
    return False

def generate_recovery_key():
    recovery_key = secrets.token_hex(16)
    salt = os.urandom(24)
    n, r, p = 2**14, 8, 1

    verifierhash = derive_recovery_verifier(recovery_key, salt, n, r, p)

    recovery_record = {
        "kdf": {"n": n, "r": r, "p": p},
        "salt": base64.b64encode(salt).decode(),
        "verifier":  base64.b64encode(verifierhash).decode()
    }

    with open(MASTER_JSON, "r") as f:
        master = json.load(f)     

    master["recovery"] = recovery_record

    with open(MASTER_JSON, "w") as f:
        json.dump(master, f, indent=2)


    print("\n" + "=" * 50)
    print("                 RECOVERY KEY")
    print("=" * 50)
    print(f"\n    {recovery_key}\n")
    print("IMPORTANT:")
    print("    This key will only be displayed once.")
    print("    Store it somewhere secure.")
    print("=" * 50 + "\n")

    return recovery_key


def validate_recovery():
    with open(MASTER_JSON, "r") as f:
        master = json.load(f)

    recovery_param = master["recovery"]

    stored_verifier = base64.b64decode(recovery_param["verifier"])
    # stored_verifier = master["recovery"["verifier"]].encode()
    salt = base64.b64decode(recovery_param["salt"])

    kdf = recovery_param["kdf"]
    n, r, p = kdf["n"], kdf["r"], kdf["p"]


    for attempt in range(3):
        recovery_code = input("Enter Recovery Key to Access Account:")

        key = derive_recovery_verifier(recovery_code, salt, n, r, p)

        if hmac.compare_digest(key, stored_verifier):
            print("Recovery Key Validated.")
            session.authenticated = True
            session.login_time = time.time()
            return True

        print("Invalid Recovery Key")

    print("Too many failed Recovery Attempts. Exiting")
    return False

def change_usb_pin():
    # Loop until user provides matching PINs or an error occurs
    while True:
        pin = getpass.getpass("Enter New USB PIN: ")

        if not pin.isdigit() or len(pin) < 4:
            print("PIN must be at least 4 digits.")
            continue
    
        pin2 = getpass.getpass("Confirm New USB PIN: ")

        if pin != pin2:
            print("Passwords do not match.")
            continue
        break

# Attempt to locate USB key file
    usb_path, _ = find_file_usb()

    if not usb_path:
        print("USB not found.")
        return False

    try:
        with open(usb_path, "w", encoding="utf-8") as f:
            usb_secret = f.read().strip()
    except (FileNotFoundError, PermissionError, OSError) as e:
        print(f"Failed to read USB key: {e}")
        return False


    if len(usb_secret) < 32:
        print("Invalid USB key.")
        return False            

    salt = os.urandom(16)
#Derivation of new key using new PIN
    derived = derive_usb_hash(usb_secret, pin, salt)

    record = {
        "salt": base64.b64encode(salt).decode(),
        "hash": base64.b64encode(derived).decode()
    }

    with open("install_usb.hash", "w") as f:
        json.dump(record, f, indent=2)

    print("USB installation complete.")
    return True




