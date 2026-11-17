from fastapi import responses
from pydantic_settings import CliUnknownArgs
from tests.conftest import TestingSessionLocal
from app.models.auth import UserAuth





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