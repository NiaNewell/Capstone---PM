
class Session:
    def __init__(self):
        self.authenticated = False
        self.login_time = None
        self.auth_method = None

session = Session()