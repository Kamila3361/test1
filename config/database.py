from pymongo.mongo_client import MongoClient
import os
import dotenv

dotenv.load_dotenv()

uri = os.getenv("DATABASE_URL")

client = MongoClient(uri)

db = client.item_db

collection = db["item_collection"]

user_collection = db["user_collection"]