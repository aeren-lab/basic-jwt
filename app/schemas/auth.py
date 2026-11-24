from pydantic import BaseModel,Field,EmailStr





class UserCreate(BaseModel):
    email:EmailStr
    password:str = Field(min_length= 8, max_length=100)

class UserResponse(BaseModel):
    id:int
    email:EmailStr
    role:str
    is_active:bool
    is_verified: bool  

    model_config ={
        "from_attributes":True
    }
class UserLogin(BaseModel):
    email:EmailStr
    password:str

class TokenResponse(BaseModel):
    access_token: str
    token_type : str ="bearer"
    refresh_token: str

class RefreshTokenRequest(BaseModel):
    refresh_token: str

class RoleUpdate(BaseModel):
    role: str

class ChangePasswordRequest(BaseModel):
    current_password: str
    new_password: str = Field(min_length=8, max_length=100)

class ForgotPasswordRequest(BaseModel):
    email: EmailStr

class ResetPasswordRequest(BaseModel):
    token: str
    new_password: str = Field(min_length=8, max_length=100)

class VerifyEmailRequest(BaseModel):
    token: str

class DeactivateAccountRequest(BaseModel):
    password: str
