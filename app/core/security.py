import re
from argon2 import PasswordHasher
from argon2.exceptions import VerificationError,VerifyMismatchError
import jwt
from datetime import datetime,timedelta,timezone
from app.core.config import settings
from uuid import uuid4

from app.models.revoked_tokens import Revokedtoken




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
    to_encode["jti"] = str(uuid4())

    token = jwt.encode(
        payload= to_encode,
        key= settings.secret_key,
        algorithm=settings.algorithm)

    return token


def create_refresh_token(data: dict, expires_delta: timedelta | None = None) -> str:
    to_encode = data.copy()

    if expires_delta:
        exp = datetime.now(timezone.utc) + expires_delta
    else:
        exp = datetime.now(timezone.utc) + timedelta(
            days=settings.refresh_token_expire_days
        )
        
    to_encode["exp"] = exp
    to_encode["type"] = "refresh"
    to_encode["jti"] = str(uuid4())

    token = jwt.encode(
        payload=to_encode,
        key=settings.secret_key,
        algorithm=settings.algorithm,
    )

    return token