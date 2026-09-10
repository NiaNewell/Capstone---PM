import time

TIMEOUT = 20 * 60 # 20 minute idle timeout

class Session:
    def __init__(self):
        self.authenticated = False
        self.login_time = None
        self.last_activity = None
        self.vault_key = None
        self.usb_secret = None


    def start(self, vault_key: bytes, usb_secret: bytes):
        self.authenticated = True
        self.login_time = time.time()
        self.last_activity = time.time()
        self.vault_key = vault_key
        self.usb_secret = usb_secret


    def touch(self):
        self.last_activity = time.time()

    def is_valid(self):
        if not self.authenticated:
            return False
        
        if time.time() - self.last_activity > TIMEOUT:
            self.clear()
            return False
        return True

    def clear(self):
        self.authenticated = False
        self.login_time = None
        self.last_activity = None
        self.vault_key = None
        self.usb_secret = None

session = Session()

