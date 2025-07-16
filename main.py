from fastapi import FastAPI, HTTPException, status, Depends
from pydantic import BaseModel, EmailStr

from config.database import collection, user_collection
from models.item import Item
from schema.schemas import list_serial
from bson import ObjectId

from models.user import UserOut, User, Token
from utils.utils import *
from jose import jwt, JWTError

from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm

app = FastAPI()

SECRET_KEY = "secret_key"
ALGORITHM = "HS256"

oauth_scheme = OAuth2PasswordBearer(tokenUrl="login")

async def get_current_user(token: str = Depends(oauth_scheme)):
    try:
        payload = jwt.decode(token, SECRET_KEY)
        user_id: str = payload.get("sub")
        if user_id == None:
            raise HTTPException(status_code = 401, detail="unauth")
        return user_collection.find_one({"_id": ObjectId(user_id)})
    except JWTError:
        raise HTTPException(status_code = 401, detail="unauth")


@app.get("/items")
def get_items():
    items = list_serial(collection.find())
    return items

@app.post("/item")
def create_item(item: Item):
    result = collection.insert_one(dict(item))
    return item

@app.put("/item/{item_id}")
def update(item_id: str, item: Item):
    result = collection.update_one({"_id": ObjectId(item_id)}, {"$set": dict(item)})
    return item

@app.post("/register")
def register(user: User) -> UserOut:
    if user_collection.find_one({"email": user.email}):
        raise HTTPException(status_code = 400, detail="Email already registered")
    
    hashed_password = hash_password(user.password)

    user_data = {"email": user.email, "password": hashed_password}
    result = user_collection.insert_one(user_data)

    return UserOut(id=str(result.inserted_id), email=user.email)

@app.post("/login")
def login(form_data: OAuth2PasswordRequestForm = Depends()):
    db_user = user_collection.find_one({"email": form_data.username})

    if not db_user or not verify_password(form_data.password, db_user["password"]):
        raise HTTPException(status_code = 401, detail="Invalid credentials")

    access_token = create_access_token(data={"sub": str(db_user["_id"])})

    return Token(access_token=access_token, token_type="bearer")

@app.get("/me")
def read_data_me(current_user: dict = Depends(get_current_user)):
    return UserOut(id = str(current_user["_id"]), email = current_user["email"])