import json
import base64
import getpass

from crypto.crypto_utils import derive_kek, unwrap
from USB.usb_installer import read_unwrap_secret
from config import MASTER_JSON


usb_secret = read_unwrap_secret()

if usb_secret is None:
    print("Could not retrieve USB secret.")
    exit()

recovery_key = input("Enter recovery key: ").strip()

with open(MASTER_JSON, "r") as f:
    master = json.load(f)

slot = master["slots"]["lost_password"]

salt = base64.b64decode(slot["salt"])

kdf = master["kdf"]

kek = derive_kek(recovery_key.encode(), usb_secret, salt, kdf["n"], kdf["r"], kdf["p"])

try:
    vault_key = unwrap(
        kek,
        base64.b64decode(slot["wrapped_key"]),
        slot["aad"]
    )

    print("RECOVERY SLOT TEST: SUCCESS")
    print("Vault key successfully unwrapped.")

except Exception:
    print("RECOVERY SLOT TEST: FAILED")