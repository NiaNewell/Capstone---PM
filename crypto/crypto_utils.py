import base64
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt


def derive_fernet_key(password, usb_secret, salt, n, r, p):
    data = f"{password}:{usb_secret}".encode()

    kdf = Scrypt(salt=salt, length=32, n=n, r=r, p=p)
    raw = kdf.derive(data)

    return base64.urlsafe_b64encode(raw)


def derive_recovery_verifier(recovery_key, salt, n, r, p):

    data = recovery_key.encode()
    kdf  = Scrypt(salt = salt, length = 32, n = n, r = r, p = p)

    return kdf.derive(data)