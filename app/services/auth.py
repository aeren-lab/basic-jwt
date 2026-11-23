from starlette.status import HTTP_401_UNAUTHORIZED
from app.core.config import settings
from app.models.auth import UserAuth
from app.models.revoked_tokens import Revokedtoken
from fastapi import HTTPException,status
from app.core.security import (hashpassword,create_access_token,
                            create_refresh_token,verify_password)
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
    access_token = create_access_token(data=data)
    refresh_token = create_refresh_token(data= data)
    return TokenResponse(
        access_token=access_token,
        token_type="bearer",
        refresh_token= refresh_token
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


def cleanup_expired_tokens_service(db) -> dict:
    revoke = db.query(Revokedtoken).filter(
            Revokedtoken.expires_at < datetime.now(timezone.utc)).delete()

    db.commit()
    return {"deleted_count":revoke }


def refresh_token_service(db,data) -> TokenResponse:
    try:
        decode_refresh_token = jwt.decode(
            jwt=data.refresh_token,
            key=settings.secret_key,
            algorithms=[settings.algorithm]
        )
    except jwt.PyJWTError:
        raise HTTPException(status_code=HTTP_401_UNAUTHORIZED,
                            detail=" refresh code is not avalivable"
        )
    refresh_token = decode_refresh_token.get("type")
    if refresh_token != "refresh":
        raise HTTPException(status_code=HTTP_401_UNAUTHORIZED,
                            detail="type is not avaibale"
        )

    user_id = decode_refresh_token.get("sub")
    jti = decode_refresh_token.get("jti")

    if user_id is None or jti is None:
        raise HTTPException(status_code=HTTP_401_UNAUTHORIZED,
                            detail=" jti or user id not avalible"
        )
    revoke = db.query(Revokedtoken).filter(Revokedtoken.jti == jti).first()

    if revoke is not None:
        raise HTTPException(status_code=HTTP_401_UNAUTHORIZED,
                            detail=" Token has been revoked"
        )
    
    user = db.query(UserAuth).filter(UserAuth.id == int(user_id)).first()
    exp = decode_refresh_token.get("exp")

    if user is None or not user.is_active or exp is None:
        raise HTTPException(status_code=HTTP_401_UNAUTHORIZED,
                            detail=" user not avalile"
        )

    new_access_token = create_access_token(data={"sub": str(user.id), "role": user.role})

    
    expires_at = datetime.fromtimestamp(float(exp), tz=timezone.utc)

    revoke_refresh = Revokedtoken(
        jti = jti,
        expires_at = expires_at
    )
    db.add(revoke_refresh)
    db.commit()

    new_refresh_token = create_refresh_token(data={"sub": str(user.id), "role": user.role})
    return TokenResponse(access_token=new_access_token, 
                    token_type="bearer", 
                    refresh_token=new_refresh_token)


    