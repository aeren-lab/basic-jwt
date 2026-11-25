from fastapi import FastAPI
from app.routers import auth
from app.core.rate_limiter import limiter
from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded

app = FastAPI()
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, 
_rate_limit_exceeded_handler) # type: ignore[arg-type]

app.include_router(auth.router)

@app.get("/")
def home():
    return {
        "message":"welcome to home"
    }

