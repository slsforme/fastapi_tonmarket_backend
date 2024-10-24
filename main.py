from fastapi import FastAPI, Depends, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session
from passlib.context import CryptContext
from pydantic import BaseModel, constr

import os
from uuid import UUID
from typing import Optional, Dict
from datetime import datetime, timedelta, timezone

from app.database import SessionLocal
from app.models import User
from app.config import origins


app = FastAPI(title="TON Market auth & registration")


app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=['*'],
    allow_headers=['*']
)

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# Security settings
pwd_context = CryptContext(schemes=['bcrypt'], deprecated='auto')
SECRET_KEY = os.getenv("SECRET_KEY")
ALGORITHM = os.getenv("ALGORITHM")
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES"))

# Pydantic models
class UserCreate(BaseModel):
    login: constr(min_length=5, max_length=50)
    password: constr(min_length=8, max_length=255)
    address: constr(min_length=40, max_length=60)
    role_id: int  

class UserOut(BaseModel):
    id: int
    uuid: UUID
    login: constr(min_length=5, max_length=50)
    password: constr(min_length=64, max_length=64)  
    address: constr(min_length=40, max_length=60)
    role_id: int

    class Config:
        from_attributes = True

def get_user_by_login(db: Session, login: str):
    return db.query(User).filter(User.login == login).first()

def create_user(db: Session, user: UserCreate) -> UserOut:
    new_user = User(
        login=user.login,
        password=user.password,
        address=user.address,
        role_id=user.role_id
    )

    db.add(new_user)
    db.commit()
    db.refresh(new_user)  

    return UserOut.from_orm(new_user)

@app.post("/register", response_model=UserOut)
def register_user(user: UserCreate, db: Session = Depends(get_db)) -> UserOut:
    db_user = db.query(User).filter(
        (User.login == user.login) |
        (User.address == user.address)
    ).first()

    if db_user:
        raise HTTPException(status_code=400, detail="User was already registered")

    return create_user(db=db, user=user)

def authenticate_user(login: str, address: str, db: Session):
    user = db.query(User).filter(
        (User.login == login) |
        (User.address == address)
    ).first()
    if not user:
        return False
    # TODO: хэшировать пароль в SHA256 на стороне фронта
    if User.password != password:  
        return False
    return user

def create_access_token(data: Dict, expires_delta: timedelta | None = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.now(timezone.UTC)
    else:
        expire = datetime.now(timezone.UTC) + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

    


if __name__ == "__main__":
    import uvicorn 
    uvicorn.run(app, host="0.0.0.0", port=8080)
    

