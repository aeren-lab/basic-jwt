from app.core.config import settings
from app.core.security import (verify_password,hashpassword,
                                create_access_token)
import jwt
import pytest
from datetime import timedelta




#1 check the vefify the password
def test_password_hashing():

    plain_password = "SuperSecret123"
    hashed = hashpassword(plain_password=plain_password)

    assert hashed != plain_password
    assert hashed  is not None

#2 check the verify the password
def test_verifyed_password():
    plain_password = "SuperSecret123"
    hashed_password = hashpassword(plain_password)
    wrong_password = "SuperSecret123123"
    

    assert verify_password(wrong_password,hashed_password) == False
    assert verify_password(plain_password,hashed_password) == True

#3 check creation of token
def test_create_access_token():
    token = create_access_token(data={"sub": "1", "role": "user"})
    decode = jwt.decode(
        jwt= token,
        key=settings.secret_key,
        algorithms=settings.algorithm
    )
    assert decode["sub"] == "1"
    assert decode["role"] =="user"
    assert decode["exp"]  !=  None

#4 check the expirey
def test_expired_access_token():
    token = create_access_token(
    data={"sub": "1"}, 
    expires_delta=timedelta(minutes=-5)
    )
    with pytest.raises(jwt.ExpiredSignatureError):
        jwt.decode(
            jwt = token,
            key= settings.secret_key,
            algorithms=[settings.algorithm]
        )

#5 check the uuid implimentation
def test_uuid_implimentation():
    data = {"sub":"1",
            "role":"user"}
    token = create_access_token(data)

    decode = jwt.decode(
        jwt = token,
        key= settings.secret_key,
        algorithms= settings.algorithm
    )
    assert decode.get("jti") != None