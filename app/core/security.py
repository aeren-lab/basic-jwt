from argon2 import PasswordHasher
from argon2.exceptions import VerificationError,VerifyMismatchError
import jwt
from datetime import datetime,timedelta,timezone
from app.core.config import settings




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


def create_access_token(data:dict,expires_delta:timedelta|None = None) -> str:

    to_encode = data.copy()

    if expires_delta:
        exp = datetime.now(timezone.utc)+expires_delta
    else:
        exp = datetime.now(timezone.utc)+timedelta(
            minutes=settings.access_token_expire_minutes
        )
    to_encode["exp"] = exp

    token = jwt.encode(
        payload= to_encode,
        key= settings.secret_key,
        algorithm=settings.algorithm)

    return token

