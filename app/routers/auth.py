from fastapi import APIRouter,Depends
from app.models.auth import UserAuth
from app.schemas.auth import (UserCreate,UserResponse,
                                UserLogin)
from app.services.auth import (user_register_service,
                                user_login_service)
from sqlalchemy.orm import Session
from app.core.database import get_db


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

@router.post("/login")
def user_login(data:UserLogin,db:Session=Depends(get_db)) -> UserResponse:
    return user_login_service(db,data)
    
