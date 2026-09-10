import base64, os
from config import MASTER_JSON
from crypto.crypto_utils import derive_kek, wrap, write_json, unwrap

n, r, p = 2**17, 8, 1


def rewrite_slots(vault_key: bytes, masterpass: str, usb_secret: bytes, recovery_key: str, rk_created: str):
    mp = masterpass.encode()
    rk = recovery_key.encode()

    slot_def = {
        "normal":           (mp, usb_secret),
        "lost_password":    (rk, usb_secret),
        "lost_usb":         (rk, mp)
    }


    slots = {}
    for name, (f1, f2) in slot_def.items():
        salt = os.urandom(16)
        aad = f"slot:{name}:v2"
        kek = derive_kek(f1, f2, salt, n, r, p)
        blob = wrap(kek, vault_key, aad)
        slots[name] = {
            "salt": base64.b64encode(salt).decode(), 
            "wrapped_key": base64.b64encode(blob).decode(),
            "aad": aad,
        }


    record = {
        "version": 2,
        "kdf": {"name": "scrypt", "n": n, "r": r, "p": p},
        "slots": slots,
        "recovery_key_created": rk_created,
    }

    write_json(MASTER_JSON, record)

    test_kek = derive_kek(
        rk,
        usb_secret,
        base64.b64decode(slots["lost_password"]["salt"]),
        n,
        r,
        p
    )

    test_vk = unwrap(
        test_kek,
        base64.b64decode(slots["lost_password"]["wrapped_key"]),
        slots["lost_password"]["aad"]
    )

    if test_vk != vault_key:
        raise ValueError("Recovery slot verification failed.")