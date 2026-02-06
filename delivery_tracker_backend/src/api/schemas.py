from __future__ import annotations

from datetime import date, datetime
from typing import Any, Literal, Optional
from uuid import UUID

from pydantic import BaseModel, EmailStr, Field


class HealthResponse(BaseModel):
    status: str = Field(..., description="Service health status")
    version: str = Field(..., description="Service version")


class VersionResponse(BaseModel):
    name: str = Field(..., description="Service name")
    version: str = Field(..., description="Service version")


class TokenPairResponse(BaseModel):
    access_token: str = Field(..., description="JWT access token")
    refresh_token: str = Field(..., description="JWT refresh token")
    token_type: str = Field("bearer", description="Token type")
    expires_in_seconds: int = Field(..., description="Access token expiry in seconds")


class LoginRequest(BaseModel):
    email: EmailStr = Field(..., description="User email")
    password: str = Field(..., min_length=1, description="User password")


class RegisterRequest(BaseModel):
    email: EmailStr = Field(..., description="User email")
    password: str = Field(..., min_length=6, description="User password (min 6 chars)")
    full_name: Optional[str] = Field(None, description="Full name")
    role: Optional[Literal["admin", "user", "driver"]] = Field(
        None, description="Role (admin only may set; otherwise defaults to user)"
    )


class RefreshRequest(BaseModel):
    refresh_token: str = Field(..., description="Refresh token")


class UserPublic(BaseModel):
    id: UUID = Field(..., description="User ID")
    email: EmailStr = Field(..., description="User email")
    full_name: Optional[str] = Field(None, description="Full name")
    role: Literal["admin", "user", "driver"] = Field(..., description="User role")
    is_active: bool = Field(..., description="Whether user is active")
    created_at: datetime = Field(..., description="Created timestamp")
    updated_at: datetime = Field(..., description="Updated timestamp")


class UserCreateAdmin(BaseModel):
    email: EmailStr = Field(..., description="User email")
    password: str = Field(..., min_length=6, description="Initial password")
    full_name: Optional[str] = Field(None, description="Full name")
    role: Literal["admin", "user", "driver"] = Field(..., description="Role")
    is_active: bool = Field(True, description="Whether user is active")


class UserUpdateAdmin(BaseModel):
    full_name: Optional[str] = Field(None, description="Full name")
    role: Optional[Literal["admin", "user", "driver"]] = Field(None, description="Role")
    is_active: Optional[bool] = Field(None, description="Whether user is active")
    password: Optional[str] = Field(None, min_length=6, description="New password (optional)")


DeliveryStatus = Literal[
    "created",
    "picked_up",
    "in_transit",
    "out_for_delivery",
    "delivered",
    "exception",
    "cancelled",
]


class DeliveryCreate(BaseModel):
    tracking_number: str = Field(..., min_length=1, description="Unique tracking number")
    user_id: UUID = Field(..., description="Owner/customer user ID")
    assigned_driver_id: Optional[UUID] = Field(None, description="Optional assigned driver user ID")
    carrier: Optional[str] = Field(None, description="Carrier name")
    title: Optional[str] = Field(None, description="Short title")
    description: Optional[str] = Field(None, description="Description")
    origin_address: Optional[str] = Field(None, description="Origin address")
    destination_address: Optional[str] = Field(None, description="Destination address")
    scheduled_delivery_date: Optional[date] = Field(None, description="Scheduled delivery date")
    current_status: Optional[DeliveryStatus] = Field(None, description="Initial status")


class DeliveryUpdate(BaseModel):
    assigned_driver_id: Optional[UUID] = Field(None, description="Assigned driver user ID")
    carrier: Optional[str] = Field(None, description="Carrier name")
    title: Optional[str] = Field(None, description="Short title")
    description: Optional[str] = Field(None, description="Description")
    origin_address: Optional[str] = Field(None, description="Origin address")
    destination_address: Optional[str] = Field(None, description="Destination address")
    scheduled_delivery_date: Optional[date] = Field(None, description="Scheduled delivery date")


class DeliveryPublic(BaseModel):
    id: UUID = Field(..., description="Delivery ID")
    tracking_number: str = Field(..., description="Tracking number")
    user_id: UUID = Field(..., description="Owner user ID")
    assigned_driver_id: Optional[UUID] = Field(None, description="Assigned driver ID")
    carrier: Optional[str] = Field(None, description="Carrier name")
    title: Optional[str] = Field(None, description="Title")
    description: Optional[str] = Field(None, description="Description")
    origin_address: Optional[str] = Field(None, description="Origin address")
    destination_address: Optional[str] = Field(None, description="Destination address")
    scheduled_delivery_date: Optional[date] = Field(None, description="Scheduled date")
    current_status: DeliveryStatus = Field(..., description="Current status")
    current_location_lat: Optional[float] = Field(None, description="Current latitude")
    current_location_lng: Optional[float] = Field(None, description="Current longitude")
    created_at: datetime = Field(..., description="Created timestamp")
    updated_at: datetime = Field(..., description="Updated timestamp")


class DeliveryStatusTransitionRequest(BaseModel):
    status: DeliveryStatus = Field(..., description="New status")
    note: Optional[str] = Field(None, description="Optional note for the event")


class LocationUpdateRequest(BaseModel):
    lat: float = Field(..., description="Latitude")
    lng: float = Field(..., description="Longitude")
    accuracy_m: Optional[float] = Field(None, description="Accuracy meters")
    speed_mps: Optional[float] = Field(None, description="Speed meters/sec")
    heading_deg: Optional[float] = Field(None, description="Heading degrees")
    source: Optional[str] = Field(None, description="Source (e.g., gps, simulator)")


class DeliveryStatusEventPublic(BaseModel):
    id: UUID = Field(..., description="Event ID")
    delivery_id: UUID = Field(..., description="Delivery ID")
    status: DeliveryStatus = Field(..., description="Status")
    occurred_at: datetime = Field(..., description="Occurred timestamp")
    note: Optional[str] = Field(None, description="Note")
    created_by_user_id: Optional[UUID] = Field(None, description="User who created this event")


class LocationPingPublic(BaseModel):
    id: UUID = Field(..., description="Ping ID")
    delivery_id: UUID = Field(..., description="Delivery ID")
    pinged_at: datetime = Field(..., description="Ping timestamp")
    lat: float = Field(..., description="Latitude")
    lng: float = Field(..., description="Longitude")
    accuracy_m: Optional[float] = Field(None, description="Accuracy meters")
    speed_mps: Optional[float] = Field(None, description="Speed meters/sec")
    heading_deg: Optional[float] = Field(None, description="Heading degrees")
    source: Optional[str] = Field(None, description="Source")


class DeliveryHistoryResponse(BaseModel):
    delivery: DeliveryPublic = Field(..., description="Delivery info")
    status_events: list[DeliveryStatusEventPublic] = Field(..., description="Status timeline")
    location_pings: list[LocationPingPublic] = Field(..., description="Location history (most recent first)")


class RealtimeMessage(BaseModel):
    type: Literal["status", "location"] = Field(..., description="Message type")
    delivery_id: UUID = Field(..., description="Delivery ID")
    payload: dict[str, Any] = Field(..., description="Message payload")
    emitted_at: datetime = Field(..., description="Server emission time")
