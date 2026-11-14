from app.core.security import verify_password
from app.models.auth import UserAuth
from fastapi import HTTPException,status
from app.core.security import hashpassword
from app.schemas.auth import UserResponse




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

def user_login_service(db,data) -> UserResponse:
    
    user= db.query(UserAuth).filter(
                                UserAuth.email == data.email).first()
    

    if not user or not verify_password(hashed_password=user.hashed_password,
                                    plain_password=data.password):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
        detail="incorrected email or password")

    return user           

    