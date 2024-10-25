from fastapi import (
    FastAPI,
    Depends,
    HTTPException,
    status,
)
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import (
    OAuth2AuthorizationCodeBearer,
    OAuth2PasswordRequestForm,
    OAuth2PasswordBearer
)
from fastapi.encoders import jsonable_encoder
from fastapi_cache import FastAPICache
from fastapi_cache.backends.redis import RedisBackend
from fastapi_cache.decorator import cache
from redis import asyncio as aioredis
from sqlalchemy.orm import Session
from passlib.context import CryptContext
from pydantic import BaseModel, constr
from jose import JWTError, jwt
import json

import os
from uuid import UUID
from typing import Optional, Dict
from datetime import datetime, timedelta, timezone

from app.database import SessionLocal
from app.models import (
    User,
    Product,
    ProductType,
)
from app.config import origins


app = FastAPI(title="TON Market auth & registration")


oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=['*'],
    allow_headers=['*']
)

app.on_event("startup")
async def startup():
    redis = aioredis.from_url("redis://localhost", encoding="utf8", decode_responses=True)
    FastAPICache.init(RedisBackend(redis), prefix="fastapi-cache")

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


# pwd_context = CryptContext(schemes=['bcrypt'], deprecated='auto')
SECRET_KEY = os.getenv("SECRET_KEY")
ALGORITHM = os.getenv("ALGORITHM")
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES"))

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
def register_user(user: UserCreate,
                 db: Session = Depends(get_db)) -> UserOut:
    db_user = db.query(User).filter(
        (User.login == user.login) |
        (User.address == user.address)
    ).first()

    if db_user:
        raise HTTPException(status_code=400,
        detail="User was already registered")

    return create_user(db=db, user=user)

def authenticate_user(login: str, db: Session):
    user = db.query(User).filter((User.login == login)).first()

    if cache is not None:
        return 
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

@app.post("/token")
def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends(),
                          db: Session = Depends(get_db)):
    user = authenticate_user(form_data.username)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect login or password",
            headers={"WWW-Authenticate": "Bearer"}
        )
        access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
        access_token = create_access_token(
            data={"sub": user.username}, expires_delta=access_token_expires
        )
        return {"access token": access_token, "token_type": "bearer"}

def verify_token(token: str = Depends(oauth2_scheme)):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise HTTPException(status_code=403, detail="Token is invalid or expired")
        return payload 
    except JWTError:
        raise HTTPException(status_code=403, detail="Token is invalid or expired")

@app.get("/verify-token/{token}")
async def verify_user_token(token: str):
    verify_token(token=token)
    return {"message": "Token is valid"}

@app.get("/api/products/")
def get_products(db: Session = Depends(get_db)):
    products = db.query(Product).all()
    return products

@app.get("/api/products/{product_id}")
@cache(3600)
async def get_product_by_id(product_id: int, db: Session = Depends(get_db)):
    product = db.query(Product).filter(Product.id == product.id).first()
    if not product:
        return HTTPException(status_code=404, detail="Product not found")
    product_data = jsonable_encoder(product)
    return product

@app.get("/api/product_types/")
def get_product_types(db: Session = Depends(get_db)):
    product_types = db.query(ProductType).all()
    return product_types


@app.get("/api/product_types/product_type_id")
@cache(3600)
async def get_product_type_by_id(product_type_id: int, db: Session = Depends(get_db)):
    product_type = db.query(ProductType).filter(ProductType.id == product_type.id).first()
    if not product_type:
        return HTTPException(status_code=404, detail="Product - Type not found")
    product_type_data = jsonable_encoder(product_type)
    return product



if __name__ == "__main__":
    import uvicorn 
    uvicorn.run(app, host="127.0.0.1", port=8000)
    

