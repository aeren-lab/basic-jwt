from app.core.security import verify_password,hashpassword

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