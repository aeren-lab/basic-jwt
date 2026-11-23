import jwt
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.database import get_db
from app.models.auth import UserAuth
from app.models.revoked_tokens import Revokedtoken

# 1. HTTPBearer tells Swagger to show a single "Value: <token>" input box!
#    auto_error=False lets us return a standard 401 Unauthorized if the header is missing.
security = HTTPBearer(auto_error=False)

# 2. Standard 401 Unauthorized exception (RFC 6750)
credentials_exception = HTTPException(
    status_code=status.HTTP_401_UNAUTHORIZED,
    detail="Could not validate credentials",
    headers={"WWW-Authenticate": "Bearer"},
)

# 3. The dependency that validates the Bearer token and returns the database user
def get_current_user(
    credentials: HTTPAuthorizationCredentials | None = Depends(security),
    db: Session = Depends(get_db)
) -> UserAuth:
    # If the user did not send the "Authorization: Bearer <token>" header at all
    if credentials is None:
        raise credentials_exception

    # Extract the raw token string from the credentials object
    token = credentials.credentials

    try:
        # Decode and verify the JWT signature & expiration
        payload = jwt.decode(
            token,
            key=settings.secret_key,
            algorithms=[settings.algorithm]
        )
        # Extract user ID from the "sub" claim
        user_id: str | None = payload.get("sub")
        jti:str | None = payload.get("jti")
        revoked = db.query(Revokedtoken).filter(
            Revokedtoken.jti == jti).first()
        if user_id is None or jti is None:
            raise credentials_exception
        elif revoked:
            raise credentials_exception
        

    except jwt.PyJWTError:
        # If token is expired, forged, or invalid
        raise credentials_exception

    # Look up the user in PostgreSQL
    user = db.query(UserAuth).filter(UserAuth.id == int(user_id)).first()
    if user is None:
        raise credentials_exception

    # Return the authenticated user
    return user

def get_current_active_user(current_user:UserAuth = Depends(
                            get_current_user)):
    if current_user.is_active:
        return current_user
    else:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="inactive user"
        )

def require_admin(current_user:UserAuth = Depends(get_current_active_user
                                                 )) -> UserAuth:
    if current_user.role == "admin":
        return current_user
    else:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN,
        detail="admin privileage required")


# Accepts a single role (e.g. "admin") or a list of roles (e.g. ["admin", "moderator"])
def require_role(allowed_roles: list[str] | str):
    roles = [allowed_roles] if isinstance(allowed_roles, str) else allowed_roles

    def role_checker(current_user: UserAuth = Depends(get_current_active_user)) -> UserAuth:
        if current_user.role not in roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Not enough permissions"
            )
        return current_user

    return role_checker