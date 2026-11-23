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

