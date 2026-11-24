from fastapi.security import http
from starlette.status import HTTP_400_BAD_REQUEST, HTTP_401_UNAUTHORIZED, HTTP_404_NOT_FOUND
from app.core.config import settings
from app.models.auth import UserAuth
from app.models.revoked_tokens import Revokedtoken
from fastapi import HTTPException,status
from app.core.security import (create_reset_token, hashpassword,create_access_token,
                            create_refresh_token,verify_password, create_email_verification_token)
from app.schemas.auth import (UserResponse, TokenResponse, ForgotPasswordRequest,
                            ResetPasswordRequest, VerifyEmailRequest, DeactivateAccountRequest)
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
    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Account is deactivated"
        )
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


def update_user_role_service(db, target_user_id: int, 
                    new_role: str, 
                    current_admin: UserAuth) -> UserAuth:


    allowed_roles = ["user", "moderator", "admin"]
    if new_role not in allowed_roles:
        raise HTTPException(status_code= HTTP_400_BAD_REQUEST,
        detail="invalid role")

    if target_user_id == current_admin.id and new_role != "admin":
        raise HTTPException(status_code= HTTP_400_BAD_REQUEST,
        detail="admins cannot demote themselves")

    user = db.query(UserAuth).filter(UserAuth.id == target_user_id).first()

    if user is None:
        raise HTTPException(status_code= HTTP_404_NOT_FOUND,
        detail="user not found")

    user.role = new_role

    db.commit()
    db.refresh(user)

    return user


def user_delete(user_id,db) -> dict:
    target_user = db.query(UserAuth).filter(UserAuth.id == user_id).first()
    if not target_user:
        raise HTTPException(status_code=404, detail="User not found")
        
    db.delete(target_user)
    db.commit()
    return {"message": f"User {user_id} deleted successfully"}

def change_password(db,data,current_user) -> dict:
    if not verify_password(data.current_password,current_user.hashed_password):
        raise HTTPException(
            status_code= HTTP_400_BAD_REQUEST,
            detail="incorrect password"
        )
    if data.current_password == data.new_password:
        raise HTTPException(
            status_code=HTTP_400_BAD_REQUEST,
            detail="new password cannot be the same as current password"
        )
    current_user.hashed_password = hashpassword(data.new_password)

    db.commit()
    return {"message": "Password changed successfully"}


def forgot_password_service(db, data: ForgotPasswordRequest) -> dict:
    user = db.query(UserAuth).filter(UserAuth.email == data.email).first()
    if not user:
        return {"message": "If this email is registered, a password reset link has been sent"}
    else:
        token = create_reset_token(user_id = user.id)
        return {"message": "Password reset token generated", "reset_token": token}

def reset_password_service(db, data: ResetPasswordRequest) -> dict:
    try:
        token = jwt.decode(
            jwt= data.token,
            key= settings.secret_key,
            algorithms=[settings.algorithm]
        )
        jti = token.get("jti")
        sub = token.get("sub")
        exp_val = token.get("exp")
        if not jti or not sub or not exp_val:
            raise HTTPException(status_code=HTTP_400_BAD_REQUEST, 
            detail="Invalid token payload")
        user_id = int(sub)
        exp = datetime.fromtimestamp(float(exp_val), tz=timezone.utc)
        
    except jwt.PyJWTError:
        raise HTTPException(
            status_code=HTTP_400_BAD_REQUEST,
            detail="invalid or expired reset token"
        )
    if token.get("type") != "reset":
        raise HTTPException(
            status_code=HTTP_400_BAD_REQUEST,
            detail="invalid token type"
        )

    check_revoke = db.query(Revokedtoken).filter(Revokedtoken.jti == jti).first()
    if check_revoke is not None:
        raise HTTPException(
            status_code= HTTP_400_BAD_REQUEST,
            detail="reset token has already been used"
        )
    user = db.query(UserAuth).filter(UserAuth.id == user_id).first()
    if not user:
        raise HTTPException(
            status_code=HTTP_404_NOT_FOUND,
            detail="user not found"
        )
    user.hashed_password = hashpassword(data.new_password)
    

    revoke = Revokedtoken(
        jti = jti,
        expires_at = exp
    )
    db.add(revoke)
    db.commit()

    return {"message": "Password reset successfully"}


def request_email_verification_service(db, current_user: UserAuth) -> dict:
    token = create_email_verification_token(user_id=current_user.id)
    return {"message": "Verification token generated", "verification_token": token}


def verify_email_service(db, data: VerifyEmailRequest) -> dict:
    try:
        token = jwt.decode(
            jwt=data.token,
            key=settings.secret_key,
            algorithms=[settings.algorithm]
        )
        jti = token.get("jti")
        sub = token.get("sub")
        exp_val = token.get("exp")
        if not jti or not sub or not exp_val:
            raise HTTPException(
                status_code=HTTP_400_BAD_REQUEST,
                detail="Invalid token payload"
            )
        user_id = int(sub)
        exp = datetime.fromtimestamp(float(exp_val), tz=timezone.utc)
    except jwt.PyJWTError:
        raise HTTPException(
            status_code=HTTP_400_BAD_REQUEST,
            detail="invalid or expired verification token"
        )

    if token.get("type") != "email_verification":
        raise HTTPException(
            status_code=HTTP_400_BAD_REQUEST,
            detail="invalid token type"
        )

    check_revoke = db.query(Revokedtoken).filter(Revokedtoken.jti == jti).first()
    if check_revoke is not None:
        raise HTTPException(
            status_code=HTTP_400_BAD_REQUEST,
            detail="verification token has already been used"
        )

    user = db.query(UserAuth).filter(UserAuth.id == user_id).first()
    if not user:
        raise HTTPException(
            status_code=HTTP_404_NOT_FOUND,
            detail="user not found"
        )

    user.is_verified = True

    revoke = Revokedtoken(
        jti=jti,
        expires_at=exp
    )
    db.add(revoke)
    db.commit()

    return {"message": "Email verified successfully"}


def deactivate_account_service(db, data: DeactivateAccountRequest, current_user: UserAuth, credentials) -> dict:
    if not verify_password(data.password, current_user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="incorrect password"
        )

    current_user.is_active = False

    if credentials and credentials.credentials:
        try:
            token_payload = jwt.decode(
                jwt=credentials.credentials,
                key=settings.secret_key,
                algorithms=[settings.algorithm]
            )
            jti = token_payload.get("jti")
            exp_val = token_payload.get("exp")
            if jti and exp_val:
                exp = datetime.fromtimestamp(float(exp_val), tz=timezone.utc)
                db.add(Revokedtoken(jti=jti, expires_at=exp))
        except jwt.PyJWTError:
            pass

    db.commit()
    return {"message": "Account deactivated successfully"}



