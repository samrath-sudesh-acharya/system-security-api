from fastapi import FastAPI
from pymongo import MongoClient
from pydantic import BaseModel
from fastapi.middleware.cors import CORSMiddleware

app = FastAPI()

# MongoDB Atlas connection string
connection_string = "mongodb+srv://demo:samrath@cluster0.o0foj0z.mongodb.net/?retryWrites=true&w=majority"
client = MongoClient(connection_string,tls=True,tlsAllowInvalidCertificates=True)


# User model for signup and signin
class User(BaseModel):
    email: str
    password: str

# Signup endpoint
@app.post("/signup")
def signup(user: User):
    # Check if user already exists
    db = client["Victim"]
    users_collection = db["users"]
    if users_collection.find_one({"username": user.email}):
        return {"message": "Username already exists"}
    
    # Create user
    user_dict = user.dict()
    users_collection.insert_one(user_dict)
    return {"message": "User created successfully"}

# Signin endpoint
@app.post("/signin")
def signin(user: User):
    # Check if user exists
    db = client.get_database("Victim")
    users_collection = db.get_collection("users")
    existing_user = users_collection.find_one({"username": user.email, "password": user.password})
    if existing_user:
        return {"message": "Login successful"}
    else:
        return {"message": "Invalid username or password"}

# Data retrieval endpoint
@app.get("/firewall_rule")
def retrieve_data():
    # Retrieve data from MongoDB
    db = client["secruity_check"]
    rules = []
    data = db["firewall_rule"].find()
    print(data[0])

    return {'_id': """ObjectId('648876eee04ee4586bf3af8a')""", 'Rule Name': 'Microsoft Edge (mDNS-In)', 'Enabled': 'Yes', 'Direction': 'In', 'Profiles': 'Domain,Private,Public', 'Grouping': 'Microsoft Edge WebView2 Runtime', 'LocalIP': 'Any', 'RemoteIP': 'Any', 'Protocol': 'UDP', 'LocalPort': '5353', 'RemotePort': 'Any', 'Edge traversal': 'No', 'Action': 'Allow'}
        
    
    # data = users_collection.find()
    # results = []
    # for item in data:
    #     results.append(item)
    # return {"data": results}


origins = ["*"]

app = CORSMiddleware(
    app=app,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)