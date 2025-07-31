from pymongo import MongoClient

client = MongoClient("mongodb://localhost:27017/")
mongo_db = client["jwt_db"]