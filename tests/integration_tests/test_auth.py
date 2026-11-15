





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