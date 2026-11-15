from pydantic import BaseModel,Field,EmailStr





class UserCreate(BaseModel):
    email:EmailStr
    password:str = Field(min_length= 8, max_length=100)

class UserResponse(BaseModel):
    id:int
    email:EmailStr
    role:str
    is_active:bool

    model_config ={
        "from_attributes":True
    }
class UserLogin(BaseModel):
    email:EmailStr
    password:str

class TokenResponse(BaseModel):
    access_token: str
    token_type : str ="bearer"