from argon2 import PasswordHasher
from argon2.exceptions import VerificationError,VerifyMismatchError




ph = PasswordHasher()

def hashpassword(plain_password) -> str:
    return ph.hash(plain_password)
    
def verify_password(plain_password,hashed_password) -> bool:
    try:
        verify = ph.verify(hash=hashed_password,
                    password= plain_password)
    except (VerificationError,VerifyMismatchError):
        return False
    return verify