from fastapi import APIRouter,Depends,Request
from app.models.auth import UserAuth
from app.schemas.auth import (UserCreate,UserResponse,
                                UserLogin,TokenResponse,
                                RefreshTokenRequest,RoleUpdate,ChangePasswordRequest,
                                ForgotPasswordRequest,ResetPasswordRequest,VerifyEmailRequest,
                                DeactivateAccountRequest, SessionResponse, LoginHistoryResponse)
from app.services.auth import (update_user_role_service, user_register_service,
                                user_login_service,
                                user_logout_service,cleanup_expired_tokens_service,
                                refresh_token_service,update_user_role_service,
                                user_delete,change_password,forgot_password_service,
                                reset_password_service,request_email_verification_service,
                                verify_email_service,deactivate_account_service,
                                get_user_sessions_service, revoke_session_service,
                                get_login_history_service)
from sqlalchemy.orm import Session
from app.core.database import get_db
from app.core.dependencies import (get_current_active_user,require_admin,security,
                    require_role, require_permission, require_verified_user)
from fastapi.security import HTTPAuthorizationCredentials
from app.core.rate_limiter import limiter


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
@limiter.limit("5/minute")
def user_login(data:UserLogin,request:Request,db:Session=Depends(get_db)) -> TokenResponse:
    user_agent = request.headers.get("user-agent")
    forwarded_for = request.headers.get("x-forwarded-for")
    if forwarded_for:
        ip_address = forwarded_for.split(",")[0].strip()
    elif request.client:
        ip_address = request.client.host
    else:
        ip_address =None
    return user_login_service(db,data,ip_address,user_agent)
    
@router.get("/me", response_model=UserResponse)
def get_my_profile(current_user: UserAuth = Depends(get_current_active_user)):
    return current_user

@router.get("/admin-only", response_model=UserResponse)
def admin_login(current_user: UserAuth = Depends(require_role(["admin"]))):
    return current_user


@router.post("/logout")
def logout(current_user:UserAuth = Depends(get_current_active_user),
            credentials: HTTPAuthorizationCredentials | None = Depends(security),
            db: Session = Depends(get_db)) -> dict:
    return user_logout_service(db, credentials)

@router.post("/cleanup-tokens")
def cleanup(current_user:UserAuth = Depends(require_admin),db=Depends(get_db)) -> dict:

    return cleanup_expired_tokens_service(db)

@router.post("/refresh", response_model=TokenResponse)
def new_access_token(data: RefreshTokenRequest,
                 db: Session = Depends(get_db)):
    return refresh_token_service(db,data)

@router.get("/moderator", response_model=UserResponse)
def moderator_dashboard(current_user: UserAuth = Depends(require_role(["admin", "moderator"]))):
    return current_user

@router.patch("/users/{user_id}/role",response_model=UserResponse)
def change_role(user_id:int,data: RoleUpdate,
        db:Session=Depends(get_db),
        current_user:UserAuth = Depends(require_role("admin"))):
    return update_user_role_service(db, user_id, data.role, current_user)

@router.get("/users", response_model=list[UserResponse])
def get_all_users(
    db: Session = Depends(get_db),
    current_user: UserAuth = Depends(require_permission("read:users"))
):
    return db.query(UserAuth).all()

@router.delete("/users/{user_id}")
def delete_user(
    user_id: int,
    db: Session = Depends(get_db),
    current_user: UserAuth = Depends(require_permission("delete:users"))):
    
    return user_delete(user_id,db)


@router.post("/change-password")
@limiter.limit("3/minute")
def password_change(request: Request, data:ChangePasswordRequest,db:Session=Depends(get_db),
                    current_user:UserAuth=Depends(get_current_active_user)):
    
    return change_password(db,data,current_user)

@router.post("/forgot-password")
@limiter.limit("5/minute")
def forgot_password(request: Request, data: ForgotPasswordRequest, db: Session = Depends(get_db)):
    return forgot_password_service(db, data)

@router.post("/reset-password")
def reset_password(data: ResetPasswordRequest, db: Session = Depends(get_db)):
    return reset_password_service(db, data)




@router.get("/verified-only", response_model=UserResponse)
def verified_only_dashboard(current_user: UserAuth = Depends(require_verified_user)):
    return current_user

@router.post("/request-verification")
def request_verification(
    current_user: UserAuth = Depends(get_current_active_user),
    db: Session = Depends(get_db)
) -> dict:
    return request_email_verification_service(db, current_user)

@router.post("/verify-email")
def verify_email(data: VerifyEmailRequest, db: Session = Depends(get_db)) -> dict:
    return verify_email_service(db, data)

@router.post("/deactivate")
def deactivate_account(
    data: DeactivateAccountRequest,
    current_user: UserAuth = Depends(get_current_active_user),
    credentials: HTTPAuthorizationCredentials | None = Depends(security),
    db: Session = Depends(get_db)
) -> dict:
    return deactivate_account_service(db, data, current_user, credentials)

@router.get("/sessions", response_model=list[SessionResponse])
def get_my_sessions(
    current_user: UserAuth = Depends(get_current_active_user),
    db: Session = Depends(get_db)
):
    return get_user_sessions_service(db, current_user)

@router.delete("/sessions/{session_id}")
def revoke_session(
    session_id: int,
    current_user: UserAuth = Depends(get_current_active_user),
    db: Session = Depends(get_db)
) -> dict:
    return revoke_session_service(db, session_id, current_user)

@router.get("/login-history", response_model=list[LoginHistoryResponse])
def get_my_login_history(
    current_user: UserAuth = Depends(get_current_active_user),
    db: Session = Depends(get_db)
):
    return get_login_history_service(db, current_user)



