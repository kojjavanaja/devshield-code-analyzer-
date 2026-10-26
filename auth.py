from datetime import datetime, timedelta, timezone
from jose import jwt, JWTError
from passlib.context import CryptContext
from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy.orm import Session
from app.core.config import SECRET_KEY, ACCESS_TOKEN_MINUTES
from app.database.session import get_db
from app.models.models import User

passwords = CryptContext(schemes=["argon2"], deprecated="auto")
oauth = OAuth2PasswordBearer(tokenUrl="/api/auth/login")
def hash_password(value: str) -> str: return passwords.hash(value)
def verify_password(value: str, hashed: str) -> bool: return passwords.verify(value, hashed)
def create_token(user_id: str) -> str:
    now = datetime.now(timezone.utc)
    return jwt.encode({"sub": user_id, "iat": now, "exp": now + timedelta(minutes=ACCESS_TOKEN_MINUTES)}, SECRET_KEY, algorithm="HS256")
def current_user(token: str = Depends(oauth), db: Session = Depends(get_db)) -> User:
    try: user_id = jwt.decode(token, SECRET_KEY, algorithms=["HS256"]).get("sub")
    except JWTError: raise HTTPException(status_code=401, detail="Invalid or expired access token")
    user = db.get(User, user_id) if user_id else None
    if not user: raise HTTPException(status_code=401, detail="Account not found")
    return user
def admin_user(user: User = Depends(current_user)) -> User:
    if user.role != "admin": raise HTTPException(status_code=403, detail="Administrator access required")
    return user
