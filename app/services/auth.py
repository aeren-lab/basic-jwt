from app.core.config import settings
from app.core.security import verify_password
from app.models import revoked_tokens
from app.models.auth import UserAuth
from app.models.revoked_tokens import Revokedtoken
from fastapi import HTTPException,status
from app.core.security import hashpassword,create_access_token
from app.schemas.auth import UserResponse,TokenResponse
import jwt
from datetime import datetime,timezone



def user_register_service(db,data) -> UserAuth:

    check_duplicate_email= db.query(UserAuth).filter(
        UserAuth.email == data.email
    ).first()
    if check_duplicate_email:

        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"{data.email} is already registed"
        )
    
    new_user = UserAuth(
        email = data.email,
        hashed_password = hashpassword(data.password),
    )

    db.add(new_user)
    db.commit()
    db.refresh(new_user)

    return new_user

def user_login_service(db,data) -> TokenResponse:
    
    user= db.query(UserAuth).filter(
                                UserAuth.email == data.email).first()
    

    if not user or not verify_password(hashed_password=user.hashed_password,
                                    plain_password=data.password):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
        detail="incorrected email or password")
    data = {"sub":str(user.id),
            "role":user.role}
    token = create_access_token(data=data)

    return TokenResponse(
    access_token=token,
    token_type="bearer"
                        )      

def user_logout_service(db,credentials) -> dict:

    token = credentials.credentials
    decode_token = jwt.decode(jwt=token,
                                key=settings.secret_key,
                                algorithms=[settings.algorithm])
    jti = decode_token.get("jti")
    encoded_exp = decode_token.get("exp")

    if not jti or not encoded_exp:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid token payload"
        )
    exp = datetime.fromtimestamp(float(encoded_exp), tz=timezone.utc)
    add_revoke = Revokedtoken(
        jti = jti,
        expires_at = exp

    )

    db.add(add_revoke)
    db.commit()

    return {"message": "Successfully logged out"}