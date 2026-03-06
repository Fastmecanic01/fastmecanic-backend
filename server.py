from fastapi import FastAPI, APIRouter, HTTPException, Depends
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from dotenv import load_dotenv
from starlette.middleware.cors import CORSMiddleware
from motor.motor_asyncio import AsyncIOMotorClient
import os
import logging
from pathlib import Path
from pydantic import BaseModel, Field
from typing import List, Optional
import uuid
from datetime import datetime, timezone
import jwt
import bcrypt

# Load environment
ROOT_DIR = Path(__file__).parent
load_dotenv(ROOT_DIR / '.env')

# MongoDB connection
mongo_url = os.environ.get('MONGO_URL', 'mongodb://localhost:27017')
db_name = os.environ.get('DB_NAME', 'fastmecanic')

client = AsyncIOMotorClient(mongo_url)
db = client[db_name]

# JWT Settings
JWT_SECRET = os.environ.get('JWT_SECRET', 'fastmechanic-secret-2024')
JWT_ALGORITHM = "HS256"

# Create app
app = FastAPI(title="Fast Mechanic API")
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
    payment_method: str
    mechanic_buys_oil: bool = False
    notes: Optional[str] = None

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

class BusinessProfile(BaseModel):
    name: str = "Jose Montufar"
    phone: str = "(562) 298-9551"
    email: str = "fastmecanic01@gmail.com"
    bio: str = "Mecanico profesional"

class WorkSchedule(BaseModel):
    day: str
    enabled: bool = True
    start_time: str = "08:00"
    end_time: str = "17:00"

class Service(BaseModel):
    id: str = ""
    name: str
    name_en: str = ""
    price: float
    duration: int = 60
    enabled: bool = True

class PaymentMethod(BaseModel):
    id: str
    name: str
    enabled: bool = True
    details: str = ""

class ServiceZone(BaseModel):
    city: str
    state: str
    enabled: bool = True

# ============ AUTH HELPERS ============

def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

def verify_password(password: str, hashed: str) -> bool:
    return bcrypt.checkpw(password.encode('utf-8'), hashed.encode('utf-8'))

def create_token(admin_id: str, username: str) -> str:
    payload = {
        "sub": admin_id,
        "username": username,
        "exp": datetime.now(timezone.utc).timestamp() + 86400
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

# ============ INIT SETTINGS ============

async def init_settings():
    existing = await db.settings.find_one({"id": "main"})
    if not existing:
        settings = {
            "id": "main",
            "profile": {"name": "Jose Montufar", "phone": "(562) 298-9551", "email": "fastmecanic01@gmail.com", "bio": "Mecanico profesional"},
            "schedule": [
                {"day": "monday", "enabled": True, "start_time": "08:00", "end_time": "17:00"},
                {"day": "tuesday", "enabled": True, "start_time": "08:00", "end_time": "17:00"},
                {"day": "wednesday", "enabled": True, "start_time": "08:00", "end_time": "17:00"},
                {"day": "thursday", "enabled": True, "start_time": "08:00", "end_time": "17:00"},
                {"day": "friday", "enabled": True, "start_time": "08:00", "end_time": "17:00"},
                {"day": "saturday", "enabled": True, "start_time": "09:00", "end_time": "14:00"},
                {"day": "sunday", "enabled": False, "start_time": "09:00", "end_time": "14:00"},
            ],
            "services": [
                {"id": "oil-conv", "name": "Cambio de Aceite Convencional", "name_en": "Conventional Oil Change", "price": 45.0, "duration": 45, "enabled": True},
                {"id": "oil-synt", "name": "Cambio de Aceite Sintetico", "name_en": "Synthetic Oil Change", "price": 75.0, "duration": 45, "enabled": True},
                {"id": "oil-semi", "name": "Cambio de Aceite Semi-Sintetico", "name_en": "Semi-Synthetic Oil Change", "price": 60.0, "duration": 45, "enabled": True},
            ],
            "payment_methods": [
                {"id": "cash", "name": "Cash", "enabled": True, "details": ""},
                {"id": "zelle", "name": "Zelle", "enabled": True, "details": ""},
                {"id": "cashapp", "name": "Cash App", "enabled": True, "details": ""},
            ],
            "service_zones": [
                {"city": "Long Beach", "state": "CA", "enabled": True},
                {"city": "Los Angeles", "state": "CA", "enabled": True},
            ]
        }
        await db.settings.insert_one(settings)

# ============ PUBLIC ROUTES ============

@api_router.get("/")
async def root():
    return {"message": "Fast Mechanic API", "status": "running"}

@api_router.get("/health")
async def health_check():
    return {"status": "healthy"}

@api_router.get("/settings/public")
async def get_public_settings():
    await init_settings()
    settings = await db.settings.find_one({"id": "main"}, {"_id": 0})
    if not settings:
        return {}
    return {
        "profile": settings.get("profile", {}),
        "schedule": [s for s in settings.get("schedule", []) if s.get("enabled")],
        "services": [s for s in settings.get("services", []) if s.get("enabled")],
        "payment_methods": [p for p in settings.get("payment_methods", []) if p.get("enabled")],
        "service_zones": [z for z in settings.get("service_zones", []) if z.get("enabled")],
    }

@api_router.post("/appointments")
async def create_appointment(data: AppointmentCreate):
    apt_id = str(uuid.uuid4())
    doc = {
        "id": apt_id,
        "customer_name": data.customer_name,
        "phone": data.phone,
        "address": data.address,
        "city": data.city,
        "state": data.state,
        "zip_code": data.zip_code,
        "vehicle": {"make": data.vehicle.make, "model": data.vehicle.model, "year": data.vehicle.year},
        "oil_type": data.oil_type,
        "appointment_date": data.appointment_date,
        "appointment_time": data.appointment_time,
        "payment_method": data.payment_method,
        "mechanic_buys_oil": data.mechanic_buys_oil,
        "notes": data.notes,
        "status": "pending",
        "created_at": datetime.now(timezone.utc).isoformat()
    }
    await db.appointments.insert_one(doc)
    doc.pop("_id", None)
    return doc

@api_router.get("/appointments/{appointment_id}")
async def get_appointment(appointment_id: str):
    doc = await db.appointments.find_one({"id": appointment_id}, {"_id": 0})
    if not doc:
        raise HTTPException(status_code=404, detail="Not found")
    return doc

# ============ ADMIN AUTH ============

@api_router.post("/admin/login")
async def admin_login(data: AdminLogin):
    admin = await db.admins.find_one({"username": data.username}, {"_id": 0})
    if not admin:
        raise HTTPException(status_code=401, detail="Invalid credentials")
    if not verify_password(data.password, admin['password_hash']):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    token = create_token(admin['id'], admin['username'])
    return {"token": token, "admin": {"id": admin['id'], "username": admin['username'], "name": admin['name']}}

@api_router.post("/admin/setup")
async def setup_admin(data: AdminCreate):
    existing = await db.admins.find_one({})
    if existing:
        raise HTTPException(status_code=400, detail="Admin already exists")
    admin_id = str(uuid.uuid4())
    doc = {
        "id": admin_id,
        "username": data.username,
        "password_hash": hash_password(data.password),
        "name": data.name,
        "created_at": datetime.now(timezone.utc).isoformat()
    }
    await db.admins.insert_one(doc)
    await init_settings()
    return {"message": "Admin created", "username": data.username}

@api_router.get("/admin/check")
async def check_admin():
    existing = await db.admins.find_one({})
    return {"exists": existing is not None}

# ============ ADMIN PROTECTED ============

@api_router.get("/admin/appointments")
async def get_all_appointments(admin = Depends(get_current_admin)):
    appointments = await db.appointments.find({}, {"_id": 0}).sort("created_at", -1).to_list(1000)
    return appointments

@api_router.patch("/admin/appointments/{appointment_id}")
async def update_appointment(appointment_id: str, data: AppointmentUpdate, admin = Depends(get_current_admin)):
    update_data = {k: v for k, v in data.dict().items() if v is not None}
    if not update_data:
        raise HTTPException(status_code=400, detail="No data")
    await db.appointments.update_one({"id": appointment_id}, {"$set": update_data})
    doc = await db.appointments.find_one({"id": appointment_id}, {"_id": 0})
    return doc

@api_router.delete("/admin/appointments/{appointment_id}")
async def delete_appointment(appointment_id: str, admin = Depends(get_current_admin)):
    result = await db.appointments.delete_one({"id": appointment_id})
    if result.deleted_count == 0:
        raise HTTPException(status_code=404, detail="Not found")
    return {"message": "Deleted"}

@api_router.get("/admin/stats")
async def get_stats(admin = Depends(get_current_admin)):
    total = await db.appointments.count_documents({})
    pending = await db.appointments.count_documents({"status": "pending"})
    confirmed = await db.appointments.count_documents({"status": "confirmed"})
    completed = await db.appointments.count_documents({"status": "completed"})
    cancelled = await db.appointments.count_documents({"status": "cancelled"})
    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    today_count = await db.appointments.count_documents({"appointment_date": today})
    return {"total": total, "pending": pending, "confirmed": confirmed, "completed": completed, "cancelled": cancelled, "today": today_count}

@api_router.get("/admin/settings")
async def get_settings(admin = Depends(get_current_admin)):
    await init_settings()
    settings = await db.settings.find_one({"id": "main"}, {"_id": 0})
    return settings

@api_router.put("/admin/settings/profile")
async def update_profile(profile: BusinessProfile, admin = Depends(get_current_admin)):
    await db.settings.update_one({"id": "main"}, {"$set": {"profile": profile.dict()}})
    return {"message": "Updated"}

@api_router.put("/admin/settings/schedule")
async def update_schedule(schedule: List[WorkSchedule], admin = Depends(get_current_admin)):
    await db.settings.update_one({"id": "main"}, {"$set": {"schedule": [s.dict() for s in schedule]}})
    return {"message": "Updated"}

@api_router.put("/admin/settings/services")
async def update_services(services: List[Service], admin = Depends(get_current_admin)):
    await db.settings.update_one({"id": "main"}, {"$set": {"services": [s.dict() for s in services]}})
    return {"message": "Updated"}

@api_router.put("/admin/settings/payment-methods")
async def update_payments(payment_methods: List[PaymentMethod], admin = Depends(get_current_admin)):
    await db.settings.update_one({"id": "main"}, {"$set": {"payment_methods": [p.dict() for p in payment_methods]}})
    return {"message": "Updated"}

@api_router.put("/admin/settings/service-zones")
async def update_zones(service_zones: List[ServiceZone], admin = Depends(get_current_admin)):
    await db.settings.update_one({"id": "main"}, {"$set": {"service_zones": [z.dict() for z in service_zones]}})
    return {"message": "Updated"}

# Include router and CORS
app.include_router(api_router)

app.add_middleware(
    CORSMiddleware,
    allow_credentials=True,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

logging.basicConfig(level=logging.INFO)

@app.on_event("shutdown")
async def shutdown():
    client.close()
