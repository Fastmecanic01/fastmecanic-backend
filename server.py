from fastapi import FastAPI, APIRouter, HTTPException, Depends
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from dotenv import load_dotenv
from starlette.middleware.cors import CORSMiddleware
from motor.motor_asyncio import AsyncIOMotorClient
import os
import logging
from pathlib import Path
from pydantic import BaseModel, Field, ConfigDict
from typing import List, Optional
import uuid
from datetime import datetime, timezone
import jwt
import bcrypt

ROOT_DIR = Path(__file__).parent
load_dotenv(ROOT_DIR / '.env')

# MongoDB connection
mongo_url = os.environ['MONGO_URL']
client = AsyncIOMotorClient(mongo_url)
db = client[os.environ['DB_NAME']]

# JWT Settings
JWT_SECRET = os.environ.get('JWT_SECRET', 'fastmechanic-secret-key-2024')
JWT_ALGORITHM = "HS256"

# Create the main app
app = FastAPI(title="Fast Mechanic API")

# Create a router with the /api prefix
api_router = APIRouter(prefix="/api")

security = HTTPBearer()

# ============ MODELS ============

class VehicleInfo(BaseModel):
    make: str
    model: str
    year: int

class AppointmentCreate(BaseModel):
    customer_name: str
    phone: str
    address: str
    city: str
    state: str
    zip_code: str
    vehicle: VehicleInfo
    oil_type: str
    appointment_date: str
    appointment_time: str
    payment_method: str  # cash, zelle, cashapp
    mechanic_buys_oil: bool = False
    notes: Optional[str] = None

class Appointment(BaseModel):
    model_config = ConfigDict(extra="ignore")
    
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    customer_name: str
    phone: str
    address: str
    city: str
    state: str
    zip_code: str
    vehicle: VehicleInfo
    oil_type: str
    appointment_date: str
    appointment_time: str
    payment_method: str
    mechanic_buys_oil: bool = False
    deposit_paid: bool = False
    notes: Optional[str] = None
    status: str = "pending"  # pending, confirmed, completed, cancelled
    created_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

class AppointmentUpdate(BaseModel):
    status: Optional[str] = None
    deposit_paid: Optional[bool] = None
    notes: Optional[str] = None

class AdminLogin(BaseModel):
    username: str
    password: str

class AdminCreate(BaseModel):
    username: str
    password: str
    name: str

class Admin(BaseModel):
    model_config = ConfigDict(extra="ignore")
    
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    username: str
    password_hash: str
    name: str
    created_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

# ============ AUTH HELPERS ============

def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

def verify_password(password: str, hashed: str) -> bool:
    return bcrypt.checkpw(password.encode('utf-8'), hashed.encode('utf-8'))

def create_token(admin_id: str, username: str) -> str:
    payload = {
        "sub": admin_id,
        "username": username,
        "exp": datetime.now(timezone.utc).timestamp() + 86400  # 24 hours
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)

async def get_current_admin(credentials: HTTPAuthorizationCredentials = Depends(security)):
    try:
        payload = jwt.decode(credentials.credentials, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        admin_id = payload.get("sub")
        if admin_id is None:
            raise HTTPException(status_code=401, detail="Invalid token")
        return payload
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid token")

# ============ PUBLIC ROUTES ============

@api_router.get("/")
async def root():
    return {"message": "Fast Mechanic API", "status": "running"}

@api_router.get("/health")
async def health_check():
    return {"status": "healthy"}

# Create appointment (public)
@api_router.post("/appointments", response_model=Appointment)
async def create_appointment(data: AppointmentCreate):
    appointment = Appointment(
        customer_name=data.customer_name,
        phone=data.phone,
        address=data.address,
        city=data.city,
        state=data.state,
        zip_code=data.zip_code,
        vehicle=data.vehicle,
        oil_type=data.oil_type,
        appointment_date=data.appointment_date,
        appointment_time=data.appointment_time,
        payment_method=data.payment_method,
        mechanic_buys_oil=data.mechanic_buys_oil,
        notes=data.notes
    )
    
    doc = appointment.model_dump()
    doc['vehicle'] = appointment.vehicle.model_dump()
    await db.appointments.insert_one(doc)
    
    return appointment

# Get appointment by ID (public - for customer confirmation)
@api_router.get("/appointments/{appointment_id}", response_model=Appointment)
async def get_appointment(appointment_id: str):
    doc = await db.appointments.find_one({"id": appointment_id}, {"_id": 0})
    if not doc:
        raise HTTPException(status_code=404, detail="Appointment not found")
    return Appointment(**doc)

# ============ ADMIN AUTH ROUTES ============

@api_router.post("/admin/login")
async def admin_login(data: AdminLogin):
    admin = await db.admins.find_one({"username": data.username}, {"_id": 0})
    if not admin:
        raise HTTPException(status_code=401, detail="Invalid credentials")
    
    if not verify_password(data.password, admin['password_hash']):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    
    token = create_token(admin['id'], admin['username'])
    return {
        "token": token,
        "admin": {
            "id": admin['id'],
            "username": admin['username'],
            "name": admin['name']
        }
    }

@api_router.post("/admin/setup")
async def setup_admin(data: AdminCreate):
    # Check if any admin exists
    existing = await db.admins.find_one({})
    if existing:
        raise HTTPException(status_code=400, detail="Admin already exists")
    
    admin = Admin(
        username=data.username,
        password_hash=hash_password(data.password),
        name=data.name
    )
    
    doc = admin.model_dump()
    await db.admins.insert_one(doc)
    
    return {"message": "Admin created successfully", "username": data.username}

@api_router.get("/admin/check")
async def check_admin_exists():
    existing = await db.admins.find_one({})
    return {"exists": existing is not None}

# ============ ADMIN PROTECTED ROUTES ============

@api_router.get("/admin/appointments", response_model=List[Appointment])
async def get_all_appointments(admin = Depends(get_current_admin)):
    appointments = await db.appointments.find({}, {"_id": 0}).sort("created_at", -1).to_list(1000)
    return [Appointment(**doc) for doc in appointments]

@api_router.get("/admin/appointments/status/{status}", response_model=List[Appointment])
async def get_appointments_by_status(status: str, admin = Depends(get_current_admin)):
    appointments = await db.appointments.find({"status": status}, {"_id": 0}).sort("appointment_date", 1).to_list(1000)
    return [Appointment(**doc) for doc in appointments]

@api_router.patch("/admin/appointments/{appointment_id}", response_model=Appointment)
async def update_appointment(appointment_id: str, data: AppointmentUpdate, admin = Depends(get_current_admin)):
    update_data = {k: v for k, v in data.model_dump().items() if v is not None}
    
    if not update_data:
        raise HTTPException(status_code=400, detail="No data to update")
    
    result = await db.appointments.update_one(
        {"id": appointment_id},
        {"$set": update_data}
    )
    
    if result.matched_count == 0:
        raise HTTPException(status_code=404, detail="Appointment not found")
    
    doc = await db.appointments.find_one({"id": appointment_id}, {"_id": 0})
    return Appointment(**doc)

@api_router.delete("/admin/appointments/{appointment_id}")
async def delete_appointment(appointment_id: str, admin = Depends(get_current_admin)):
    result = await db.appointments.delete_one({"id": appointment_id})
    if result.deleted_count == 0:
        raise HTTPException(status_code=404, detail="Appointment not found")
    return {"message": "Appointment deleted"}

@api_router.get("/admin/stats")
async def get_dashboard_stats(admin = Depends(get_current_admin)):
    total = await db.appointments.count_documents({})
    pending = await db.appointments.count_documents({"status": "pending"})
    confirmed = await db.appointments.count_documents({"status": "confirmed"})
    completed = await db.appointments.count_documents({"status": "completed"})
    cancelled = await db.appointments.count_documents({"status": "cancelled"})
    
    # Get today's appointments
    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    today_count = await db.appointments.count_documents({"appointment_date": today})
    
    return {
        "total": total,
        "pending": pending,
        "confirmed": confirmed,
        "completed": completed,
        "cancelled": cancelled,
        "today": today_count
    }

@api_router.get("/admin/me")
async def get_current_admin_info(admin = Depends(get_current_admin)):
    admin_doc = await db.admins.find_one({"id": admin['sub']}, {"_id": 0, "password_hash": 0})
    if not admin_doc:
        raise HTTPException(status_code=404, detail="Admin not found")
    return admin_doc

# Include the router in the main app
app.include_router(api_router)

app.add_middleware(
    CORSMiddleware,
    allow_credentials=True,
    allow_origins=os.environ.get('CORS_ORIGINS', '*').split(','),
    allow_methods=["*"],
    allow_headers=["*"],
)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

@app.on_event("shutdown")
async def shutdown_db_client():
    client.close()
