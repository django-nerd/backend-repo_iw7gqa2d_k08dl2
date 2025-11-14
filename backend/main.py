from fastapi import FastAPI, HTTPException, Depends, UploadFile, File, Form
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel
from typing import Optional, List, Dict
from datetime import datetime, timedelta
from jose import JWTError, jwt
from passlib.context import CryptContext
import io
import qrcode
from reportlab.pdfgen import canvas
from reportlab.lib.pagesizes import letter
from reportlab.lib.units import inch
from reportlab.lib.utils import ImageReader
from PIL import Image
import base64
import os

from schemas import (
    User, Visitor, Appointment, Pass as PassModel, CheckLog,
    AuthRequest, AuthResponse, InviteRequest, ApproveAppointmentRequest,
    IssuePassRequest, QRVerifyRequest, Pagination, Organization
)
from database import db, create_document, get_documents

SECRET_KEY = os.getenv("SECRET_KEY", "super-secret-key")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 12

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/login")

app = FastAPI(title="Visitor Pass Management API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Utility functions

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password):
    return pwd_context.hash(password)

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

async def get_current_user(token: str = Depends(oauth2_scheme)) -> dict:
    credentials_exception = HTTPException(
        status_code=401,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        user_id: str = payload.get("sub")
        if user_id is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception
    # fetch user from db
    users = await get_documents("user", {"_id": user_id}, limit=1)
    if not users:
        raise credentials_exception
    return users[0]


def require_roles(*roles):
    async def role_checker(user: dict = Depends(get_current_user)):
        if user.get("role") not in roles:
            raise HTTPException(status_code=403, detail="Insufficient permissions")
        return user
    return role_checker

# Health
@app.get("/test")
async def test():
    # also validates db connection
    await get_documents("user", {}, limit=1)
    return {"ok": True}

# Auth
@app.post("/auth/register", response_model=AuthResponse)
async def register(req: AuthRequest):
    # very simple: create user if not exists
    existing = await get_documents("user", {"email": req.email}, limit=1)
    if existing:
        raise HTTPException(400, detail="Email already registered")
    user = {
        "email": req.email,
        "name": req.email.split("@")[0],
        "role": "admin",
        "password_hash": get_password_hash(req.password),
        "created_at": datetime.utcnow(),
        "updated_at": datetime.utcnow(),
    }
    created = await create_document("user", user)
    token = create_access_token({"sub": created["_id"]})
    return AuthResponse(access_token=token)

@app.post("/auth/login", response_model=AuthResponse)
async def login(form_data: OAuth2PasswordRequestForm = Depends()):
    users = await get_documents("user", {"email": form_data.username}, limit=1)
    if not users:
        raise HTTPException(401, detail="Invalid credentials")
    user = users[0]
    if not verify_password(form_data.password, user.get("password_hash", "")):
        raise HTTPException(401, detail="Invalid credentials")
    token = create_access_token({"sub": user["_id"], "role": user.get("role")})
    return AuthResponse(access_token=token)

# Visitors
@app.post("/visitors")
async def create_visitor(full_name: str = Form(...), email: Optional[str] = Form(None), phone: Optional[str] = Form(None), company: Optional[str] = Form(None), gov_id: Optional[str] = Form(None), photo: Optional[UploadFile] = File(None), user=Depends(require_roles("admin","employee","security"))):
    photo_url = None
    if photo is not None:
        # simple in-memory image handling; store base64 as placeholder
        img_bytes = await photo.read()
        b64 = base64.b64encode(img_bytes).decode()
        photo_url = f"data:{photo.content_type};base64,{b64}"
    doc = {
        "full_name": full_name,
        "email": email,
        "phone": phone,
        "company": company,
        "gov_id": gov_id,
        "photo_url": photo_url,
        "created_at": datetime.utcnow(),
        "updated_at": datetime.utcnow(),
    }
    created = await create_document("visitor", doc)
    return created

@app.get("/visitors")
async def list_visitors(q: Optional[str] = None, limit: int = 20, page: int = 1, user=Depends(require_roles("admin","employee","security"))):
    filter_dict: Dict = {}
    if q:
        filter_dict = {"$or": [
            {"full_name": {"$regex": q, "$options": "i"}},
            {"email": {"$regex": q, "$options": "i"}},
            {"phone": {"$regex": q, "$options": "i"}},
        ]}
    docs = await get_documents("visitor", filter_dict, limit=limit)
    return {"items": docs, "page": page, "limit": limit}

# Appointments
@app.post("/appointments")
async def create_appointment(req: InviteRequest, user=Depends(require_roles("employee","admin"))):
    # create or reuse visitor by email if exists
    visitor_doc = None
    if req.visitor_email:
        exists = await get_documents("visitor", {"email": req.visitor_email}, limit=1)
        if exists:
            visitor_doc = exists[0]
    if not visitor_doc:
        visitor_doc = await create_document("visitor", {
            "full_name": req.visitor_name,
            "email": req.visitor_email,
            "phone": req.visitor_phone,
            "created_at": datetime.utcnow(),
            "updated_at": datetime.utcnow(),
        })
    appt = {
        "host_user_id": user["_id"],
        "visitor_id": visitor_doc["_id"],
        "purpose": req.purpose,
        "scheduled_at": req.scheduled_at,
        "status": "pending",
        "created_at": datetime.utcnow(),
        "updated_at": datetime.utcnow(),
    }
    created = await create_document("appointment", appt)
    return created

@app.post("/appointments/{appointment_id}/approve")
async def approve_appointment(appointment_id: str, req: ApproveAppointmentRequest, user=Depends(require_roles("employee","admin"))):
    # simple update: set status
    # Using get_documents as read helper; in real app we'd have update function
    appts = await get_documents("appointment", {"_id": appointment_id}, limit=1)
    if not appts:
        raise HTTPException(404, detail="Appointment not found")
    appt = appts[0]
    appt["status"] = "approved" if req.approve else "rejected"
    appt["updated_at"] = datetime.utcnow()
    # naive approach: create a new document version (demo purpose)
    await create_document("appointment", appt)
    return {"ok": True}

# Pass issuance
@app.post("/passes/issue")
async def issue_pass(req: IssuePassRequest, user=Depends(require_roles("security","admin"))):
    token = base64.urlsafe_b64encode(os.urandom(24)).decode().rstrip("=")
    qr = qrcode.QRCode(version=1, box_size=10, border=4)
    qr.add_data(token)
    qr.make(fit=True)
    img = qr.make_image(fill_color="black", back_color="white")

    # Generate PDF badge
    pdf_buffer = io.BytesIO()
    c = canvas.Canvas(pdf_buffer, pagesize=letter)
    c.setFont("Helvetica-Bold", 16)
    c.drawString(1*inch, 10*inch, "Visitor Pass")
    c.setFont("Helvetica", 12)
    c.drawString(1*inch, 9.5*inch, f"Visitor ID: {req.visitor_id}")
    if req.valid_to:
        c.drawString(1*inch, 9.2*inch, f"Valid To: {req.valid_to}")
    qr_bytes = io.BytesIO()
    img.save(qr_bytes, format="PNG")
    qr_bytes.seek(0)
    c.drawInlineImage(ImageReader(qr_bytes), 1*inch, 7.5*inch, 2*inch, 2*inch)
    c.showPage()
    c.save()
    pdf_buffer.seek(0)
    pdf_b64 = base64.b64encode(pdf_buffer.getvalue()).decode()
    pdf_url = f"data:application/pdf;base64,{pdf_b64}"

    pass_doc = {
        "visitor_id": req.visitor_id,
        "appointment_id": req.appointment_id,
        "qr_token": token,
        "pdf_url": pdf_url,
        "valid_from": req.valid_from or datetime.utcnow(),
        "valid_to": req.valid_to,
        "status": "issued",
        "created_at": datetime.utcnow(),
        "updated_at": datetime.utcnow(),
    }
    created = await create_document("pass", pass_doc)
    return created

# QR verify + check-in/out
@app.post("/passes/verify")
async def verify_pass(req: QRVerifyRequest):
    results = await get_documents("pass", {"qr_token": req.token}, limit=1)
    if not results:
        raise HTTPException(404, detail="Invalid QR token")
    p = results[0]
    return {"valid": True, "pass": p}

@app.post("/passes/{pass_id}/check")
async def check_pass(pass_id: str, action: str, user=Depends(require_roles("security","admin"))):
    if action not in ("check_in", "check_out"):
        raise HTTPException(400, detail="Invalid action")
    passes = await get_documents("pass", {"_id": pass_id}, limit=1)
    if not passes:
        raise HTTPException(404, detail="Pass not found")
    p = passes[0]
    p["status"] = "checked_in" if action == "check_in" else "checked_out"
    p["updated_at"] = datetime.utcnow()
    await create_document("pass", p)
    log = {
        "pass_id": pass_id,
        "action": action,
        "scanned_by": user["_id"],
        "created_at": datetime.utcnow(),
    }
    await create_document("checklog", log)
    return {"ok": True}

# Simple reporting endpoints
@app.get("/reports/checklogs")
async def list_checklogs(limit: int = 50, user=Depends(require_roles("admin","security"))):
    logs = await get_documents("checklog", {}, limit=limit)
    return {"items": logs}

@app.get("/me")
async def me(user=Depends(get_current_user)):
    return user
