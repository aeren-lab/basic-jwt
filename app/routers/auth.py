from fastapi import APIRouter




router = APIRouter(prefix="/auth",
                   tags=["auth"] )

@router("/")
def greet():
    return {
        "message":"this is auth router"
    }
