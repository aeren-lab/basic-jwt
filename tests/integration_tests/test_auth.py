from operator import mod
from app.core.config import settings
from app.models import revoked_tokens
from app.models.revoked_tokens import Revokedtoken
from tests.conftest import TestingSessionLocal
from app.models.auth import UserAuth
import jwt

from datetime import timedelta,datetime,timezone



#1 test the register the user

def test_register_user_success(client):
    response = client.post("/auth/register",json=
    {"email": "newuser@example.com", "password": "StrongPassword123"})

    assert response.status_code == 200
    assert response.json()["email"] == "newuser@example.com"

#2 test the registration duplicated email
def test_register_duplicate_email(client):
    response = client.post("/auth/register" ,json=
    {"email": "newuser@example.com", "password": "StrongPassword123"
    })

    assert response.status_code == 200
    response = client.post("/auth/register" ,json=
    {"email": "newuser@example.com", "password": "StrongPassword123"
    })

    assert response.status_code == 400

#3 test the login sucess
def test_login_sucess(client):
    response = client.post("/auth/register", json={
    "email": "newuser@example.com",
    "password": "StrongPassword123"
    })

    assert response.status_code == 200
    response = client.post("/auth/login", json={
    "email": "newuser@example.com",
    "password": "StrongPassword123"
    })

    assert response.status_code == 200
    assert "access_token" in response.json()
    assert response.json()["token_type"] ==  "bearer"

#4  rest login worong password
def test_login_wrong_password(client):
    response = client.post("/auth/register", json={
        "email":"newuser@example.com", "password": "StrongPassword123" })

    assert response.status_code == 200

    response = client.post("/auth/login", json={
        "email":"newuser@example.com", "password": "StrongPassword" })

    assert response.status_code == 401

#5 test login with wrong email
def test_login_user_not_found(client):
    response = client.post("/auth/register", json={
        "email":"newuser@example.com", "password": "StrongPassword123" })

    assert response.status_code == 200

    response = client.post("/auth/login", json={
        "email":"wrong@example.com", "password": "StrongPassword123" })

    assert response.status_code == 401

#6 test the /me in sucessfull case

def test_get_my_profile_success(client):
    data = {"email":"me@example.com","password":"password123"}
    client.post("/auth/register",json=data)
    login_res = client.post("/auth/login",json=data)
    token = login_res.json()["access_token"]
    response = client.get("/auth/me",headers={"Authorization":f"Bearer {token}"})

    assert response.status_code == 200
    assert response.json()["email"] == "me@example.com"

#7 test the me without token
def test_get_my_profile_missing_token(client):
    response = client.get("/auth/me")
    assert response.status_code == 401

#8 test invalid tokens
def test_get_my_profile_invalid_token(client):
    response = client.get("/auth/me", headers={"Authorization": "Bearer fake.token.here"})
    assert response.status_code == 401


# 9. Test accessing /me with an inactive user account
def test_get_my_profile_inactive_user(client):
    # Step 1: Register and log in to get a valid token
    data = {"email": "banned@example.com", "password": "password123"}
    client.post("/auth/register", json=data)
    login_res = client.post("/auth/login", json=data)
    token = login_res.json()["access_token"]

    # Step 2: Simulate an admin deactivating this account in the database
    db = TestingSessionLocal()
    user = db.query(UserAuth).filter(UserAuth.email == "banned@example.com").first()
    assert user is not None 
    user.is_active = False
    db.commit()
    db.close()

    # Step 3: Try to access /auth/me with the token
    response = client.get("/auth/me", headers={"Authorization": f"Bearer {token}"})

    # Step 4: Verify it was blocked
    assert response.status_code == 400
    assert response.json()["detail"] == "inactive user"

#10 test admin only 
def test_admin_required(client):
    client.post("/auth/register",json={"email":"me@example.com",
                                        "password":"password123",
                                        })
    db = TestingSessionLocal()
    user = db.query(UserAuth).filter(UserAuth.email == "me@example.com").first()
    assert user is not None 
    user.role = "admin"
    db.commit()
    db.close()

    login_res = client.post("/auth/login",json={"email":"me@example.com",
                                        "password":"password123"})
    token = login_res.json()["access_token"]

    

    response = client.get("/auth/admin-only",headers={"Authorization":f"Bearer {token}"})

    assert response.status_code == 200

#11 test the admin access with user
def test_admin_access_with_user(client):
    data ={"email":"me@example.com","password":"password123"}
    client.post("/auth/register",json=data)
    res = client.post("/auth/login",json=data)

    token = res.json()["access_token"]
    response = client.get("/auth/admin-only",headers= {"Authorization":f"Bearer {token}"})

    assert response.status_code == 403

#12 test the logout
def test_logout_success(client):
    data ={"email":"me@example.com","password":"password123"}
    client.post("/auth/register",json=data)
    login = client.post("/auth/login",json=data)
    token = login.json()["access_token"]

    response = client.post("/auth/logout",headers={"Authorization":f"Bearer {token}"})

    assert response.status_code == 200
    assert response.json()["message"] == "Successfully logged out"

    response = client.get("/auth/me",headers={"Authorization":f"Bearer {token}"})

    assert response.status_code == 401

#14 test the clean up
def test_expired_revoked_tokens(client):
    data = {"email":"me@example.com","password":"password123"}

    client.post("/auth/register",json=data)

    db = TestingSessionLocal()
    user = db.query(UserAuth).filter(UserAuth.email == "me@example.com").first()
    assert user is not None 
    user.role = "admin"
    db.commit()
    db.close()
    
    res =client.post("/auth/login",json=data)

    token = res.json()["access_token"]

    db = TestingSessionLocal()
    expired_token = Revokedtoken(
        jti="expired-test-jti",
        expires_at=datetime.now(timezone.utc) - timedelta(minutes=5)
    )
    db.add(expired_token)
    db.commit()
    db.close()
    


    client.post("/auth/cleanup-tokens",headers={"Authorization":f"Bearer {token}"})

    response = db.query(Revokedtoken).filter(Revokedtoken.jti == "expired-test-jti").first()
    db.close() 
    
    assert response == None

# 15 test the refresh token
def test_refresh_token_success(client):
    data ={"email":"me@example.com","password":"password123"}
    client.post("/auth/register",json=data)
    login = client.post("/auth/login",json=data)
    refresh_token = login.json()["refresh_token"]

    response = client.post("/auth/refresh", json={"refresh_token": refresh_token})

    assert response.status_code == 200

    new_token = response.json()["access_token"]

    response = client.get("/auth/me",headers={"Authorization": f"Bearer {new_token}"})

    assert response.status_code == 200
    

# 16 test_refresh_with_access_token_fails
def test_refresh_with_access_token_fails(client):
    data = {"email": "me@example.com", "password": "password123"}
    client.post("/auth/register", json=data)
    login = client.post("/auth/login", json=data)
    
    # Extract the access_token (its type is NOT "refresh")
    access_token = login.json()["access_token"]

    # Try using the access token on the refresh endpoint
    response = client.post("/auth/refresh", json={"refresh_token": access_token})

    # Must be rejected with 401 Unauthorized
    assert response.status_code == 401

# 17 test_refresh_token_rotation
def test_refresh_token_rotation(client):
    data = {"email": "me@example.com", "password": "password123"}
    client.post("/auth/register", json=data)
    login = client.post("/auth/login", json=data)
    old_refresh_token = login.json()["refresh_token"]

    # 1. First refresh succeeds and gives a brand NEW refresh token
    res1 = client.post("/auth/refresh", json={"refresh_token": old_refresh_token})
    assert res1.status_code == 200
    new_refresh_token = res1.json()["refresh_token"]
    assert new_refresh_token != old_refresh_token  # Proves token was rotated!

    # 2. Reusing the OLD refresh token is immediately rejected with 401!
    res2 = client.post("/auth/refresh", json={"refresh_token": old_refresh_token})
    assert res2.status_code == 401

    # 3. Using the NEW refresh token succeeds!
    res3 = client.post("/auth/refresh", json={"refresh_token": new_refresh_token})
    assert res3.status_code == 200


#18 test the rule based authorification
def test_role_based_access(client):
    data = {"email": "me@example.com", "password": "password123"}

    #user login and try to access the moderater or admin end points
    client.post("/auth/register",json=data)
    res = client.post("/auth/login",json=data)
    token = res.json()["access_token"]

    response = client.get("/auth/moderator",headers={"Authorization": f"Bearer {token}"})

    assert response.status_code == 403

    #chanage the user role into moderatro
    db = TestingSessionLocal()
    moderator = db.query(UserAuth).filter(UserAuth.id == 1).first()
    assert moderator is not None
    moderator.role = "moderator"
    db.add(moderator)
    db.commit()
    db.close()

    #test the moderater access
    response = client.get("/auth/moderator",headers={"Authorization": f"Bearer {token}"})

    assert response.status_code == 200

    #moderator check the admin only end point
    response = client.get("/auth/admin-only",headers={"Authorization": f"Bearer {token}"})
    
    assert response.status_code == 403

    #change the moderator in to admin
    db = TestingSessionLocal()
    moderator = db.query(UserAuth).filter(UserAuth.id == 1).first()
    assert moderator is not None
    moderator.role = "admin"
    db.add(moderator)
    db.commit()
    db.close()

    #test the admin access
    response = client.get("/auth/moderator",headers={"Authorization": f"Bearer {token}"})

    assert response.status_code == 200

#19 test the update role through the admin
def test_admin_can_promote_user(client):
    data = {"email": "me@example.com", "password": "password123"}
    data1 = {"email": "admin@example.com", "password": "password123"}

    client.post("/auth/register",json=data)
    client.post("/auth/register",json=data1)

    #chnge the data 1 to admin
    db = TestingSessionLocal()
    moderator = db.query(UserAuth).filter(UserAuth.id == 2).first()
    assert moderator is not None
    moderator.role = "admin"
    db.add(moderator)
    db.commit()
    db.close()

    admin = client.post("/auth/login",json=data1)
    admin_token = admin.json()["access_token"]

    response = client.patch(
    "/auth/users/1/role",
    headers={"Authorization": f"Bearer {admin_token}"},
    json={"role": "moderator"}
        )

    assert response.status_code == 200
    assert response.json()["role"] == "moderator"


#20 check user can chane to admin
def test_user_cannot_change_role(client):
    data = {"email": "me@example.com", "password": "password123"}
    data1 = {"email": "admin@example.com", "password": "password123"}

    client.post("/auth/register",json=data)
    client.post("/auth/register",json=data1)

    res = client.post("/auth/login",json=data1)
    token = res.json()["access_token"]

    response = client.patch(
    "/auth/users/1/role",
    headers={"Authorization": f"Bearer {token}"},
    json={"role": "moderator"}
        )

    assert response.status_code == 403
    

#21 test admin can demote themself
def test_admin_cannot_demote_themselves(client):
    data = {"email": "me@example.com", "password": "password123"}
    data1 = {"email": "admin@example.com", "password": "password123"}

    client.post("/auth/register",json=data)
    client.post("/auth/register",json=data1)

    #chnge the data 1 to admin
    db = TestingSessionLocal()
    moderator = db.query(UserAuth).filter(UserAuth.id == 2).first()
    assert moderator is not None
    moderator.role = "admin"
    db.add(moderator)
    db.commit()
    db.close()

    admin = client.post("/auth/login",json=data1)
    admin_token = admin.json()["access_token"]

    response = client.patch(
    "/auth/users/2/role",
    headers={"Authorization": f"Bearer {admin_token}"},
    json={"role": "moderator"}
        )

    assert response.status_code == 400
    assert response.json()["detail"] == "admins cannot demote themselves"


#22 test_role_ignored_during_registration
def test_role_ignored_during_registration(client):
    data = {"email": "me@example.com", "password": "password123","role": "admin"}
    
    response = client.post("/auth/register",json=data)

  

    
    
    assert response.status_code == 200
    assert response.json()["role"] == "user"


# 23 test read:users permission for regular users
def test_read_users_permission_success(client):
    data = {"email": "user@example.com", "password": "password123"}
    client.post("/auth/register", json=data)
    login_res = client.post("/auth/login", json=data)
    token = login_res.json()["access_token"]

    response = client.get("/auth/users", headers={"Authorization": f"Bearer {token}"})
    assert response.status_code == 200
    assert isinstance(response.json(), list)
    assert len(response.json()) >= 1


# 24 test normal user cannot delete users (missing delete:users)
def test_delete_user_forbidden_for_normal_user(client):
    user1 = {"email": "user1@example.com", "password": "password123"}
    user2 = {"email": "user2@example.com", "password": "password123"}
    client.post("/auth/register", json=user1)
    client.post("/auth/register", json=user2)

    login_res = client.post("/auth/login", json=user1)
    token = login_res.json()["access_token"]

    response = client.delete("/auth/users/2", headers={"Authorization": f"Bearer {token}"})
    assert response.status_code == 403
    assert "delete:users" in response.json()["detail"]


# 25 test moderator cannot delete users (has read & write, but missing delete:users)
def test_delete_user_forbidden_for_moderator(client):
    mod_data = {"email": "mod@example.com", "password": "password123"}
    user_data = {"email": "target@example.com", "password": "password123"}
    client.post("/auth/register", json=mod_data)
    client.post("/auth/register", json=user_data)

    # Promote mod to "moderator" in database
    db = TestingSessionLocal()
    mod = db.query(UserAuth).filter(UserAuth.email == "mod@example.com").first()
    assert mod is not None
    mod.role = "moderator"
    db.commit()
    db.close()

    login_res = client.post("/auth/login", json=mod_data)
    token = login_res.json()["access_token"]

    response = client.delete("/auth/users/2", headers={"Authorization": f"Bearer {token}"})
    assert response.status_code == 403
    assert "delete:users" in response.json()["detail"]


# 26 test admin can delete users (has delete:users)
def test_delete_user_success_for_admin(client):
    admin_data = {"email": "admin@example.com", "password": "password123"}
    user_data = {"email": "victim@example.com", "password": "password123"}
    client.post("/auth/register", json=admin_data)
    client.post("/auth/register", json=user_data)

    # Promote admin to "admin" in database
    db = TestingSessionLocal()
    admin = db.query(UserAuth).filter(UserAuth.email == "admin@example.com").first()
    assert admin is not None
    admin.role = "admin"
    db.commit()
    db.close()

    login_res = client.post("/auth/login", json=admin_data)
    token = login_res.json()["access_token"]

    response = client.delete("/auth/users/2", headers={"Authorization": f"Bearer {token}"})
    assert response.status_code == 200
    assert response.json()["message"] == "User 2 deleted successfully"

    # Verify user 2 was actually removed from database
    db = TestingSessionLocal()
    deleted_user = db.query(UserAuth).filter(UserAuth.id == 2).first()
    db.close()
    assert deleted_user is None

# 27 test the password successs
def test_change_password_success(client):
    data = {"email": "admin@example.com", "password": "OldPassword123"}
    client.post("/auth/register",json=data)

    res = client.post("/auth/login",json= data)

    token = res.json()["access_token"]

    response = client.post("/auth/change-password",headers={"Authorization": f"Bearer {token}"},
                    json={"current_password":"OldPassword123",
                    "new_password" :"new_password",})

    assert response.status_code == 200

    response = client.post("/auth/login",json=data)

    assert response.status_code == 401

    response = client.post("/auth/login",json={"email": "admin@example.com", "password": "new_password"})

    assert response.status_code == 200

# 28 test wrong current password fails
def test_change_password_wrong_current_password(client):
    data = {"email": "user@example.com", "password": "OldPassword123"}
    client.post("/auth/register", json=data)
    login_res = client.post("/auth/login", json=data)
    token = login_res.json()["access_token"]

    response = client.post(
        "/auth/change-password",
        headers={"Authorization": f"Bearer {token}"},
        json={"current_password": "WrongPassword999", "new_password": "NewValidPassword123"}
    )

    assert response.status_code == 400
    assert response.json()["detail"] == "incorrect password"


# 29 test same new password as old fails
def test_change_password_same_as_old_fails(client):
    data = {"email": "user@example.com", "password": "OldPassword123"}
    client.post("/auth/register", json=data)
    login_res = client.post("/auth/login", json=data)
    token = login_res.json()["access_token"]

    response = client.post(
        "/auth/change-password",
        headers={"Authorization": f"Bearer {token}"},
        json={"current_password": "OldPassword123", "new_password": "OldPassword123"}
    )

    assert response.status_code == 400
    assert response.json()["detail"] == "new password cannot be the same as current password"


# 30 test new password too short fails validation
def test_change_password_too_short_fails(client):
    data = {"email": "user@example.com", "password": "OldPassword123"}
    client.post("/auth/register", json=data)
    login_res = client.post("/auth/login", json=data)
    token = login_res.json()["access_token"]

    response = client.post(
        "/auth/change-password",
        headers={"Authorization": f"Bearer {token}"},
        json={"current_password": "OldPassword123", "new_password": "short"}
    )

    assert response.status_code == 422


# 31 test forgot password generates token for valid email
def test_forgot_password_success(client):
    data = {"email": "user@example.com", "password": "Password123"}
    client.post("/auth/register", json=data)

    response = client.post("/auth/forgot-password", json={"email": "user@example.com"})
    assert response.status_code == 200
    assert "reset_token" in response.json()
    assert response.json()["message"] == "Password reset token generated"


# 32 test forgot password does not leak non-existent emails (user enumeration defense)
def test_forgot_password_unknown_email(client):
    response = client.post("/auth/forgot-password", json={"email": "nonexistent@example.com"})
    assert response.status_code == 200
    assert "reset_token" not in response.json()
    assert response.json()["message"] == "If this email is registered, a password reset link has been sent"


# 33 test reset password with valid token updates password
def test_reset_password_success(client):
    data = {"email": "user@example.com", "password": "OldPassword123"}
    client.post("/auth/register", json=data)

    forgot_res = client.post("/auth/forgot-password", json={"email": "user@example.com"})
    token = forgot_res.json()["reset_token"]

    reset_res = client.post(
        "/auth/reset-password",
        json={"token": token, "new_password": "NewBrandPassword123"}
    )
    assert reset_res.status_code == 200
    assert reset_res.json()["message"] == "Password reset successfully"

    # Old password no longer works
    login_old = client.post("/auth/login", json=data)
    assert login_old.status_code == 401

    # New password works
    login_new = client.post("/auth/login", json={"email": "user@example.com", "password": "NewBrandPassword123"})
    assert login_new.status_code == 200


# 34 test reset token is single-use and cannot be reused
def test_reset_password_token_is_single_use(client):
    data = {"email": "user@example.com", "password": "OldPassword123"}
    client.post("/auth/register", json=data)

    forgot_res = client.post("/auth/forgot-password", json={"email": "user@example.com"})
    token = forgot_res.json()["reset_token"]

    # First reset succeeds
    res1 = client.post(
        "/auth/reset-password",
        json={"token": token, "new_password": "NewBrandPassword123"}
    )
    assert res1.status_code == 200

    # Second reset with SAME token fails
    res2 = client.post(
        "/auth/reset-password",
        json={"token": token, "new_password": "AnotherNewPassword123"}
    )
    assert res2.status_code == 400
    assert res2.json()["detail"] == "reset token has already been used"


# 35 test reset password rejects non-reset tokens (e.g. access token)
def test_reset_password_wrong_token_type(client):
    data = {"email": "user@example.com", "password": "Password123"}
    client.post("/auth/register", json=data)
    login_res = client.post("/auth/login", json=data)
    access_token = login_res.json()["access_token"]

    response = client.post(
        "/auth/reset-password",
        json={"token": access_token, "new_password": "NewBrandPassword123"}
    )
    assert response.status_code == 400
    assert response.json()["detail"] == "invalid token type"


# 36 test email verification flow and require_verified_user dependency
def test_email_verification_flow(client):
    data = {"email": "verifyuser@example.com", "password": "Password123"}
    reg_res = client.post("/auth/register", json=data)
    assert reg_res.status_code == 200
    assert reg_res.json()["is_verified"] is False

    login_res = client.post("/auth/login", json=data)
    token = login_res.json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}

    # Verified-only route fails with 403 before verification
    unverified_access = client.get("/auth/verified-only", headers=headers)
    assert unverified_access.status_code == 403
    assert unverified_access.json()["detail"] == "Email verification required"

    # Request verification token
    req_res = client.post("/auth/request-verification", headers=headers)
    assert req_res.status_code == 200
    assert "verification_token" in req_res.json()
    verification_token = req_res.json()["verification_token"]

    # Verify email with token
    verify_res = client.post("/auth/verify-email", json={"token": verification_token})
    assert verify_res.status_code == 200
    assert verify_res.json()["message"] == "Email verified successfully"

    # Profile shows verified
    me_res = client.get("/auth/me", headers=headers)
    assert me_res.status_code == 200
    assert me_res.json()["is_verified"] is True

    # Verified-only route now succeeds with 200
    verified_access = client.get("/auth/verified-only", headers=headers)
    assert verified_access.status_code == 200
    assert verified_access.json()["email"] == "verifyuser@example.com"


# 37 test verification token is single-use and cannot be reused
def test_verify_email_single_use(client):
    data = {"email": "singleuse@example.com", "password": "Password123"}
    client.post("/auth/register", json=data)
    login_res = client.post("/auth/login", json=data)
    token = login_res.json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}

    req_res = client.post("/auth/request-verification", headers=headers)
    verification_token = req_res.json()["verification_token"]

    # First verification succeeds
    res1 = client.post("/auth/verify-email", json={"token": verification_token})
    assert res1.status_code == 200

    # Second verification fails
    res2 = client.post("/auth/verify-email", json={"token": verification_token})
    assert res2.status_code == 400
    assert res2.json()["detail"] == "verification token has already been used"


# 38 test verify email rejects wrong token types (e.g. access token)
def test_verify_email_wrong_token_type(client):
    data = {"email": "wrongtype@example.com", "password": "Password123"}
    client.post("/auth/register", json=data)
    login_res = client.post("/auth/login", json=data)
    token = login_res.json()["access_token"]

    res = client.post("/auth/verify-email", json={"token": token})
    assert res.status_code == 400
    assert res.json()["detail"] == "invalid token type"


# 39 test verify email rejects invalid/tampered token
def test_verify_email_invalid_token(client):
    res = client.post("/auth/verify-email", json={"token": "invalid.tampered.token"})
    assert res.status_code == 400
    assert res.json()["detail"] == "invalid or expired verification token"


# 40 test deactivate account success revokes token and marks user inactive
def test_deactivate_account_success(client):
    data = {"email": "deactivate_me@example.com", "password": "Password123"}
    client.post("/auth/register", json=data)
    login_res = client.post("/auth/login", json=data)
    token = login_res.json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}

    # Deactivate account with valid password
    deact_res = client.post(
        "/auth/deactivate",
        json={"password": "Password123"},
        headers=headers
    )
    assert deact_res.status_code == 200
    assert deact_res.json()["message"] == "Account deactivated successfully"

    # Subsequent access with revoked token is rejected
    me_res = client.get("/auth/me", headers=headers)
    assert me_res.status_code == 401

    # Login attempt for deactivated account is blocked
    login_again = client.post("/auth/login", json=data)
    assert login_again.status_code == 400
    assert login_again.json()["detail"] == "Account is deactivated"


# 41 test deactivate account with wrong password fails
def test_deactivate_account_wrong_password(client):
    data = {"email": "keep_active@example.com", "password": "Password123"}
    client.post("/auth/register", json=data)
    login_res = client.post("/auth/login", json=data)
    token = login_res.json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}

    # Deactivate with incorrect password
    deact_res = client.post(
        "/auth/deactivate",
        json={"password": "WrongPassword123"},
        headers=headers
    )
    assert deact_res.status_code == 400
    assert deact_res.json()["detail"] == "incorrect password"

    # User remains active and can access /auth/me
    me_res = client.get("/auth/me", headers=headers)
    assert me_res.status_code == 200
    assert me_res.json()["email"] == "keep_active@example.com"


# 42 test login rejected when account is deactivated
def test_login_deactivated_account_rejected(client):
    data = {"email": "inactive_login@example.com", "password": "Password123"}
    client.post("/auth/register", json=data)
    login_res = client.post("/auth/login", json=data)
    token = login_res.json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}

    client.post("/auth/deactivate", json={"password": "Password123"}, headers=headers)

    # Logging in with correct credentials fails with 400
    res = client.post("/auth/login", json=data)
    assert res.status_code == 400
    assert res.json()["detail"] == "Account is deactivated"









