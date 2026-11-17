from fastapi import APIRouter,Depends
from app.models.auth import UserAuth
from app.schemas.auth import (UserCreate,UserResponse,
                                UserLogin,TokenResponse)
from app.services.auth import (user_register_service,
                                user_login_service,
                                user_logout_service)
from sqlalchemy.orm import Session
from app.core.database import get_db
from app.core.dependencies import get_current_active_user,require_admin,security
from fastapi.security import HTTPAuthorizationCredentials


router = APIRouter(prefix="/auth",
                   tags=["auth"] )

@router.get("/")
def greet() -> dict:
    return {
        "message":"this is auth router"
    }

@router.post("/register")
def register(data:UserCreate,
                db:Session=Depends(get_db)) :
    return user_register_service(db,data)

@router.post("/login",response_model=TokenResponse)
def user_login(data:UserLogin,db:Session=Depends(get_db)) -> TokenResponse:
    return user_login_service(db,data)
    
@router.get("/me", response_model=UserResponse)
def get_my_profile(current_user: UserAuth = Depends(get_current_active_user)):
    return current_user

@router.get("/admin-only",response_model=UserResponse)
def admin_login(current_user:UserAuth = Depends(require_admin)):
    return current_user

@router.post("/logout")
def logout(current_user:UserAuth = Depends(get_current_active_user),
            credentials: HTTPAuthorizationCredentials | None = Depends(security),
            db: Session = Depends(get_db)) -> dict:
    return user_logout_service(db, credentials)
