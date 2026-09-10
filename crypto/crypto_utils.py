import base64, os, json, tempfile
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def generate_vk():
    return os.urandom(32)


def derive_kek(f1: bytes, f2: bytes, salt: bytes, n: int, r: int, p: int) -> bytes: 
    material = len(f1).to_bytes(4, "big") + f1 + len(f2).to_bytes(4, "big") + f2
    kdf = Scrypt(salt = salt, length = 32, n=n, r=r, p=p)
    return kdf.derive(material)


def wrap(kek: bytes, plaintext: bytes, aad: str) -> bytes:
   nonce = os.urandom(12)
   aesgcm = AESGCM(kek)
   ciphertext =  aesgcm.encrypt(nonce, plaintext, aad.encode())
   return nonce + ciphertext


def unwrap(kek: bytes, data: bytes, aad: str) -> bytes:
    nonce = data[:12]
    ciphertext = data[12:]
    aesgcm = AESGCM(kek)
    return aesgcm.decrypt(nonce, ciphertext, aad.encode())


def write_json(path: str, data: dict):
    dir_name = os.path.dirname(path) or "."
    fd, tmp_path = tempfile.mkstemp(dir = dir_name)
    try: 
        with os.fdopen(fd, "w") as f:
                    json.dump(data, f, indent=2)
                    f.flush()
                    os.fsync(f.fileno())
        os.replace(tmp_path, path)  # atomic on the same filesystem
    except Exception:
        os.remove(tmp_path)
        raise