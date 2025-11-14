from pydantic import BaseModel, EmailStr, Field
from typing import Optional, List
from datetime import datetime

# Each model's class name determines the collection name (lowercased)

class Organization(BaseModel):
    id: Optional[str] = Field(None, alias="_id")
    name: str
    domain: Optional[str] = None
    address: Optional[str] = None
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None

class User(BaseModel):
    id: Optional[str] = Field(None, alias="_id")
    org_id: Optional[str] = None
    name: str
    email: EmailStr
    role: str  # admin, security, employee, visitor
    password_hash: Optional[str] = None
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None

class Visitor(BaseModel):
    id: Optional[str] = Field(None, alias="_id")
    org_id: Optional[str] = None
    full_name: str
    email: Optional[EmailStr] = None
    phone: Optional[str] = None
    company: Optional[str] = None
    photo_url: Optional[str] = None
    gov_id: Optional[str] = None
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None

class Appointment(BaseModel):
    id: Optional[str] = Field(None, alias="_id")
    org_id: Optional[str] = None
    host_user_id: str
    visitor_id: str
    purpose: Optional[str] = None
    scheduled_at: datetime
    status: str = "pending"  # pending, approved, rejected, completed, cancelled
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None

class Pass(BaseModel):
    id: Optional[str] = Field(None, alias="_id")
    org_id: Optional[str] = None
    appointment_id: Optional[str] = None
    visitor_id: str
    qr_token: str
    pdf_url: Optional[str] = None
    valid_from: Optional[datetime] = None
    valid_to: Optional[datetime] = None
    status: str = "issued"  # issued, checked_in, checked_out, revoked, expired
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None

class CheckLog(BaseModel):
    id: Optional[str] = Field(None, alias="_id")
    org_id: Optional[str] = None
    pass_id: str
    action: str  # check_in or check_out
    scanned_by: Optional[str] = None  # user id of security/frontdesk
    location: Optional[str] = None
    created_at: Optional[datetime] = None

class AuthRequest(BaseModel):
    email: EmailStr
    password: str

class AuthResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"

class InviteRequest(BaseModel):
    visitor_name: str
    visitor_email: Optional[EmailStr]
    visitor_phone: Optional[str]
    purpose: Optional[str]
    scheduled_at: datetime

class ApproveAppointmentRequest(BaseModel):
    approve: bool

class IssuePassRequest(BaseModel):
    visitor_id: str
    appointment_id: Optional[str] = None
    valid_from: Optional[datetime] = None
    valid_to: Optional[datetime] = None

class QRVerifyRequest(BaseModel):
    token: str

class Pagination(BaseModel):
    q: Optional[str] = None
    limit: int = 20
    page: int = 1
