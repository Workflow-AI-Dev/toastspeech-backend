from fastapi import FastAPI, HTTPException, Depends, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, EmailStr
from typing import Optional, List
from datetime import datetime, timedelta
import os
from dotenv import load_dotenv
from supabase import create_client, Client
from passlib.context import CryptContext
from jose import jwt, JWTError

# Load env vars
load_dotenv()

# Supabase setup
SUPABASE_URL = os.getenv("SUPABASE_URL")
SUPABASE_SERVICE_KEY = os.getenv("SUPABASE_SERVICE_KEY")
SECRET_KEY = os.getenv("JWT_SECRET_KEY", "super-secret-key")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

if not SUPABASE_URL or not SUPABASE_SERVICE_KEY:
    raise ValueError("Supabase env variables not set")

supabase: Client = create_client(SUPABASE_URL, SUPABASE_SERVICE_KEY)

# Password hashing
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
security = HTTPBearer()

# FastAPI app init
app = FastAPI(title="ToastSpeech API", version="1.0")

# CORS setup
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # ← Replace with frontend URL in production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Models
class UserSignUp(BaseModel):
    name: str
    email: EmailStr
    password: str
    gender: Optional[str] = None
    age_group: Optional[str] = None
    profession: Optional[str] = None
    purposes: Optional[List[str]] = None
    custom_purpose: Optional[str] = None

class UserSignIn(BaseModel):
    email: EmailStr
    password: str

class UserResponse(BaseModel):
    id: str
    name: str
    email: str
    gender: Optional[str]
    age_group: Optional[str]
    profession: Optional[str]
    purposes: Optional[List[str]]
    custom_purpose: Optional[str]
    subscription_plan: Optional[str]
    subscription_status: Optional[str]
    created_at: Optional[str]

class TokenResponse(BaseModel):
    access_token: str
    token_type: str
    message: str
    user: UserResponse

# Utility functions
def hash_password(password: str) -> str:
    return pwd_context.hash(password)

def verify_password(plain: str, hashed: str) -> bool:
    return pwd_context.verify(plain, hashed)

def create_token(data: dict, expires_minutes: int = ACCESS_TOKEN_EXPIRE_MINUTES):
    expire = datetime.utcnow() + timedelta(minutes=expires_minutes)
    to_encode = {**data, "exp": expire}
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)):
    try:
        payload = jwt.decode(credentials.credentials, SECRET_KEY, algorithms=[ALGORITHM])
        user_id = payload.get("sub")
        if not user_id:
            raise Exception("Invalid token")

        result = supabase.table("users").select("*").eq("id", user_id).single().execute()
        return result.data
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid or expired token")

# Routes
@app.get("/health")
def health():
    return {"status": "ok", "timestamp": datetime.utcnow().isoformat()}

@app.post("/auth/signup", response_model=TokenResponse)
def signup(data: UserSignUp):
    existing = supabase.table("users").select("email").eq("email", data.email).execute()
    if existing.data:
        raise HTTPException(status_code=400, detail="Email already in use")

    # Create Supabase auth user
    auth = supabase.auth.admin.create_user({
        "email": data.email,
        "password": data.password,
        "email_confirm": True
    })

    if not auth.user:
        raise HTTPException(status_code=400, detail="Auth creation failed")

    user_id = auth.user.id
    profile = {
        "id": user_id,
        "name": data.name,
        "email": data.email,
        "gender": data.gender,
        "age_group": data.age_group,
        "profession": data.profession,
        "purposes": data.purposes,
        "custom_purpose": data.custom_purpose,
        "subscription_plan": "free",
        "subscription_status": "active"
    }

    supabase.table("users").insert(profile).execute()

    # Optional: Add default usage tracking
    now = datetime.now()
    supabase.table("subscription_usage").insert({
        "user_id": user_id,
        "month": now.month,
        "year": now.year,
        "speeches_limit": 1,
        "speeches_used": 0,
        "evaluations_limit": 1,
        "evaluations_used": 0
    }).execute()

    token = create_token({"sub": user_id, "email": data.email})

    return TokenResponse(
        access_token=token,
        token_type="bearer",
        message="Signup successful",
        user=UserResponse(**profile, created_at=datetime.utcnow().isoformat())
    )

@app.post("/auth/signin", response_model=TokenResponse)
def signin(data: UserSignIn):
    auth = supabase.auth.sign_in_with_password({
        "email": data.email,
        "password": data.password
    })

    if not auth.user:
        raise HTTPException(status_code=401, detail="Invalid credentials")

    user_id = auth.user.id
    res = supabase.table("users").select("*").eq("id", user_id).single().execute()

    if not res.data:
        raise HTTPException(status_code=404, detail="User profile not found")

    token = create_token({"sub": user_id, "email": data.email})

    return TokenResponse(
        access_token=token,
        token_type="bearer",
        message="Signin successful",
        user=UserResponse(**res.data)
    )

@app.get("/auth/me", response_model=UserResponse)
def me(current_user: dict = Depends(get_current_user)):
    return UserResponse(**current_user)

# Entry point for local testing (not needed on Render)
if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
