from __future__ import annotations

import os
from datetime import datetime, timezone
from typing import Any, Optional
from uuid import UUID

from fastapi import Depends, FastAPI, HTTPException, Query, WebSocket, WebSocketDisconnect, status
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from src.api.db import apply_schema_if_needed, get_db_session
from src.api.deps import CurrentUser, get_current_user, require_admin, require_driver_or_admin
from src.api.realtime import realtime_hub
from src.api.schemas import (
    DeliveryCreate,
    DeliveryHistoryResponse,
    DeliveryPublic,
    DeliveryStatusEventPublic,
    DeliveryStatusTransitionRequest,
    DeliveryUpdate,
    HealthResponse,
    LocationPingPublic,
    LocationUpdateRequest,
    LoginRequest,
    RefreshRequest,
    RegisterRequest,
    TokenPairResponse,
    UserCreateAdmin,
    UserPublic,
    UserUpdateAdmin,
    VersionResponse,
)
from src.api.security import (
    hash_password,
    issue_access_token,
    issue_refresh_token,
    sha256_token_hash,
    verify_password,
)

APP_VERSION = os.getenv("APP_VERSION", "0.1.0")

openapi_tags = [
    {"name": "meta", "description": "Health/version and documentation helper endpoints."},
    {"name": "auth", "description": "Authentication: login/register/refresh/logout."},
    {"name": "deliveries", "description": "User and driver delivery operations."},
    {"name": "admin", "description": "Admin-only user and delivery management."},
    {"name": "realtime", "description": "Realtime delivery updates over WebSocket."},
]

app = FastAPI(
    title="Delivery Tracker Backend",
    description=(
        "Backend API for the Delivery Tracker app.\n\n"
        "Realtime:\n"
        "- WebSocket endpoint: /realtime/ws\n"
        "- Client sends JSON commands:\n"
        "  {\"action\":\"subscribe\",\"delivery_id\":\"<uuid>\"}\n"
        "  {\"action\":\"unsubscribe\",\"delivery_id\":\"<uuid>\"}\n"
        "Server emits JSON messages:\n"
        "  {\"type\":\"status\"|\"location\", \"delivery_id\":\"<uuid>\", \"payload\":{...}, \"emitted_at\":\"...\"}\n"
    ),
    version=APP_VERSION,
    openapi_tags=openapi_tags,
)

# CORS: allow frontend access. If FRONTEND_ORIGIN is set, use it; otherwise allow all (dev-friendly).
frontend_origin = os.getenv("FRONTEND_ORIGIN")
allow_origins = [frontend_origin] if frontend_origin else ["*"]

app.add_middleware(
    CORSMiddleware,
    allow_origins=allow_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.on_event("startup")
async def _startup() -> None:
    # Apply schema+seed if needed (safe to run multiple times).
    await apply_schema_if_needed()


# -----------------------
# Meta endpoints
# -----------------------

@app.get(
    "/health",
    tags=["meta"],
    summary="Health endpoint",
    response_model=HealthResponse,
)
def health() -> HealthResponse:
    """Return service health."""
    return HealthResponse(status="ok", version=APP_VERSION)


@app.get(
    "/version",
    tags=["meta"],
    summary="Version endpoint",
    response_model=VersionResponse,
)
def version() -> VersionResponse:
    """Return service version information."""
    return VersionResponse(name="delivery-tracker-backend", version=APP_VERSION)


@app.get(
    "/docs/realtime",
    tags=["meta"],
    summary="Realtime usage help",
    description="Human-readable help for the realtime WebSocket endpoint.",
)
def realtime_help() -> dict[str, Any]:
    """Return realtime WebSocket usage instructions."""
    return {
        "websocket_url": "/realtime/ws",
        "subscribe_message": {"action": "subscribe", "delivery_id": "<uuid>"},
        "unsubscribe_message": {"action": "unsubscribe", "delivery_id": "<uuid>"},
        "server_message": {"type": "status|location", "delivery_id": "<uuid>", "payload": {}, "emitted_at": "<iso8601>"},
        "auth": "Provide access token as query param: ?token=<JWT_ACCESS_TOKEN>",
    }


# -----------------------
# Auth endpoints
# -----------------------

@app.post(
    "/auth/register",
    tags=["auth"],
    summary="Register new user",
    response_model=UserPublic,
)
async def register(
    body: RegisterRequest,
    session: AsyncSession = Depends(get_db_session),
) -> UserPublic:
    """Register a new user account. Role defaults to 'user'."""
    # Only allow non-admin role creation here.
    role = body.role or "user"
    if role != "user":
        role = "user"

    password_hash = hash_password(body.password)

    try:
        res = await session.execute(
            text(
                """
                INSERT INTO users (email, password_hash, full_name, role)
                VALUES (:email, :password_hash, :full_name, :role)
                RETURNING id, email, full_name, role, is_active, created_at, updated_at
                """
            ),
            {
                "email": str(body.email).lower(),
                "password_hash": password_hash,
                "full_name": body.full_name,
                "role": role,
            },
        )
        await session.commit()
    except Exception:
        await session.rollback()
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Email already registered")

    row = res.mappings().one()
    return UserPublic(**row)


@app.post(
    "/auth/login",
    tags=["auth"],
    summary="Login and receive access+refresh tokens",
    response_model=TokenPairResponse,
)
async def login(body: LoginRequest, session: AsyncSession = Depends(get_db_session)) -> TokenPairResponse:
    """Authenticate user credentials; returns access+refresh tokens."""
    res = await session.execute(
        text("SELECT id, email, password_hash, role, is_active FROM users WHERE email = :email"),
        {"email": str(body.email).lower()},
    )
    row = res.mappings().first()
    if not row or not bool(row["is_active"]):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")

    if not verify_password(body.password, str(row["password_hash"])):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")

    user_id = str(row["id"])
    role = str(row["role"])

    access = issue_access_token(user_id=user_id, role=role)
    refresh, refresh_exp = issue_refresh_token(user_id=user_id, role=role)

    # Store refresh hash
    token_hash = sha256_token_hash(refresh)
    await session.execute(
        text(
            """
            INSERT INTO refresh_tokens (user_id, token_hash, expires_at)
            VALUES (:user_id, :token_hash, :expires_at)
            """
        ),
        {"user_id": user_id, "token_hash": token_hash, "expires_at": refresh_exp},
    )
    await session.commit()

    access_ttl_seconds = int(os.getenv("JWT_ACCESS_TTL_MINUTES", "30")) * 60
    return TokenPairResponse(
        access_token=access,
        refresh_token=refresh,
        expires_in_seconds=access_ttl_seconds,
    )


@app.post(
    "/auth/refresh",
    tags=["auth"],
    summary="Refresh access token using refresh token",
    response_model=TokenPairResponse,
)
async def refresh_tokens(body: RefreshRequest, session: AsyncSession = Depends(get_db_session)) -> TokenPairResponse:
    """Validate refresh token, rotate it, and return a new access+refresh token pair."""
    from src.api.security import decode_and_validate_token  # local import to avoid cycles in docs

    try:
        payload = decode_and_validate_token(body.refresh_token, expected_type="refresh")
    except Exception:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid refresh token")

    user_id = str(payload.get("sub"))
    role = str(payload.get("role"))

    token_hash = sha256_token_hash(body.refresh_token)

    res = await session.execute(
        text(
            """
            SELECT id, revoked_at, expires_at
            FROM refresh_tokens
            WHERE token_hash = :token_hash AND user_id = :user_id
            """
        ),
        {"token_hash": token_hash, "user_id": user_id},
    )
    row = res.mappings().first()
    if not row:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Refresh token not recognized")

    if row["revoked_at"] is not None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Refresh token revoked")

    if row["expires_at"] <= datetime.now(timezone.utc):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Refresh token expired")

    # Rotate: revoke old, insert new
    await session.execute(
        text("UPDATE refresh_tokens SET revoked_at = NOW() WHERE id = :id"),
        {"id": str(row["id"])},
    )

    new_access = issue_access_token(user_id=user_id, role=role)
    new_refresh, new_refresh_exp = issue_refresh_token(user_id=user_id, role=role)
    await session.execute(
        text("INSERT INTO refresh_tokens (user_id, token_hash, expires_at) VALUES (:user_id, :token_hash, :expires_at)"),
        {"user_id": user_id, "token_hash": sha256_token_hash(new_refresh), "expires_at": new_refresh_exp},
    )
    await session.commit()

    access_ttl_seconds = int(os.getenv("JWT_ACCESS_TTL_MINUTES", "30")) * 60
    return TokenPairResponse(
        access_token=new_access,
        refresh_token=new_refresh,
        expires_in_seconds=access_ttl_seconds,
    )


@app.post(
    "/auth/logout",
    tags=["auth"],
    summary="Logout (revoke refresh token)",
)
async def logout(body: RefreshRequest, session: AsyncSession = Depends(get_db_session)) -> dict[str, Any]:
    """Revoke a refresh token."""
    token_hash = sha256_token_hash(body.refresh_token)
    await session.execute(
        text("UPDATE refresh_tokens SET revoked_at = NOW() WHERE token_hash = :token_hash"),
        {"token_hash": token_hash},
    )
    await session.commit()
    return {"ok": True}


@app.get(
    "/me",
    tags=["auth"],
    summary="Get current user profile",
    response_model=UserPublic,
)
async def me(user: CurrentUser = Depends(get_current_user), session: AsyncSession = Depends(get_db_session)) -> UserPublic:
    """Return the authenticated user's profile."""
    res = await session.execute(
        text("SELECT id, email, full_name, role, is_active, created_at, updated_at FROM users WHERE id = :id"),
        {"id": str(user.id)},
    )
    row = res.mappings().one()
    return UserPublic(**row)


# -----------------------
# Deliveries (user/driver)
# -----------------------

def _ensure_delivery_access(user: CurrentUser, delivery_row: dict[str, Any]) -> None:
    """
    Rules:
      - admin can access all
      - owner (delivery.user_id) can access
      - assigned driver can access
    """
    if user.role == "admin":
        return
    if str(delivery_row["user_id"]) == str(user.id):
        return
    if delivery_row.get("assigned_driver_id") and str(delivery_row["assigned_driver_id"]) == str(user.id):
        return
    raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Not authorized for this delivery")


@app.get(
    "/deliveries",
    tags=["deliveries"],
    summary="List deliveries for current user (or assigned driver); admin can filter",
    response_model=list[DeliveryPublic],
)
async def list_deliveries(
    session: AsyncSession = Depends(get_db_session),
    user: CurrentUser = Depends(get_current_user),
    status_filter: Optional[str] = Query(None, description="Optional status filter"),
) -> list[DeliveryPublic]:
    """List deliveries visible to the current user."""
    params: dict[str, Any] = {}
    where = []

    if status_filter:
        where.append("d.current_status = :status")
        params["status"] = status_filter

    if user.role != "admin":
        where.append("(d.user_id = :uid OR d.assigned_driver_id = :uid)")
        params["uid"] = str(user.id)

    where_sql = "WHERE " + " AND ".join(where) if where else ""
    res = await session.execute(text(f"SELECT * FROM deliveries d {where_sql} ORDER BY d.updated_at DESC"), params)
    rows = res.mappings().all()
    return [DeliveryPublic(**r) for r in rows]


@app.get(
    "/deliveries/{delivery_id}",
    tags=["deliveries"],
    summary="Get delivery details",
    response_model=DeliveryPublic,
)
async def get_delivery(
    delivery_id: UUID,
    session: AsyncSession = Depends(get_db_session),
    user: CurrentUser = Depends(get_current_user),
) -> DeliveryPublic:
    """Get delivery by id if authorized."""
    res = await session.execute(text("SELECT * FROM deliveries WHERE id = :id"), {"id": str(delivery_id)})
    row = res.mappings().first()
    if not row:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Delivery not found")
    _ensure_delivery_access(user, row)
    return DeliveryPublic(**row)


@app.get(
    "/deliveries/by-tracking/{tracking_number}",
    tags=["deliveries"],
    summary="Get delivery by tracking number",
    response_model=DeliveryPublic,
)
async def get_delivery_by_tracking(
    tracking_number: str,
    session: AsyncSession = Depends(get_db_session),
    user: CurrentUser = Depends(get_current_user),
) -> DeliveryPublic:
    """Lookup delivery by tracking_number if authorized."""
    res = await session.execute(text("SELECT * FROM deliveries WHERE tracking_number = :tn"), {"tn": tracking_number})
    row = res.mappings().first()
    if not row:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Delivery not found")
    _ensure_delivery_access(user, row)
    return DeliveryPublic(**row)


@app.post(
    "/deliveries/{delivery_id}/status",
    tags=["deliveries"],
    summary="Transition delivery status",
    response_model=DeliveryPublic,
)
async def transition_status(
    delivery_id: UUID,
    body: DeliveryStatusTransitionRequest,
    session: AsyncSession = Depends(get_db_session),
    user: CurrentUser = Depends(require_driver_or_admin),
) -> DeliveryPublic:
    """
    Update delivery status and append a status event.
    Allowed for driver/admin *only* (owner cannot change status).
    """
    res = await session.execute(text("SELECT * FROM deliveries WHERE id = :id"), {"id": str(delivery_id)})
    delivery = res.mappings().first()
    if not delivery:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Delivery not found")

    # driver can only update assigned deliveries
    if user.role != "admin":
        if not delivery.get("assigned_driver_id") or str(delivery["assigned_driver_id"]) != str(user.id):
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Driver not assigned to this delivery")

    await session.execute(
        text("UPDATE deliveries SET current_status = :st WHERE id = :id"),
        {"st": body.status, "id": str(delivery_id)},
    )
    await session.execute(
        text(
            """
            INSERT INTO delivery_status_events (delivery_id, status, note, created_by_user_id)
            VALUES (:delivery_id, :status, :note, :created_by_user_id)
            """
        ),
        {"delivery_id": str(delivery_id), "status": body.status, "note": body.note, "created_by_user_id": str(user.id)},
    )

    # Return updated delivery
    res2 = await session.execute(text("SELECT * FROM deliveries WHERE id = :id"), {"id": str(delivery_id)})
    updated = res2.mappings().one()
    await session.commit()

    # Realtime event
    await realtime_hub.publish(
        delivery_id=delivery_id,
        message_type="status",
        payload={"status": body.status, "note": body.note},
    )

    return DeliveryPublic(**updated)


@app.post(
    "/deliveries/{delivery_id}/location",
    tags=["deliveries"],
    summary="Update delivery location",
    response_model=DeliveryPublic,
)
async def update_location(
    delivery_id: UUID,
    body: LocationUpdateRequest,
    session: AsyncSession = Depends(get_db_session),
    user: CurrentUser = Depends(require_driver_or_admin),
) -> DeliveryPublic:
    """
    Update delivery's current location and add a location ping.
    Allowed for driver/admin *only*; driver must be assigned.
    """
    res = await session.execute(text("SELECT * FROM deliveries WHERE id = :id"), {"id": str(delivery_id)})
    delivery = res.mappings().first()
    if not delivery:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Delivery not found")

    if user.role != "admin":
        if not delivery.get("assigned_driver_id") or str(delivery["assigned_driver_id"]) != str(user.id):
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Driver not assigned to this delivery")

    await session.execute(
        text(
            """
            UPDATE deliveries
            SET current_location_lat = :lat, current_location_lng = :lng
            WHERE id = :id
            """
        ),
        {"lat": body.lat, "lng": body.lng, "id": str(delivery_id)},
    )
    await session.execute(
        text(
            """
            INSERT INTO location_pings (delivery_id, lat, lng, accuracy_m, speed_mps, heading_deg, source)
            VALUES (:delivery_id, :lat, :lng, :accuracy_m, :speed_mps, :heading_deg, :source)
            """
        ),
        {
            "delivery_id": str(delivery_id),
            "lat": body.lat,
            "lng": body.lng,
            "accuracy_m": body.accuracy_m,
            "speed_mps": body.speed_mps,
            "heading_deg": body.heading_deg,
            "source": body.source,
        },
    )

    res2 = await session.execute(text("SELECT * FROM deliveries WHERE id = :id"), {"id": str(delivery_id)})
    updated = res2.mappings().one()
    await session.commit()

    await realtime_hub.publish(
        delivery_id=delivery_id,
        message_type="location",
        payload={"lat": body.lat, "lng": body.lng, "accuracy_m": body.accuracy_m, "source": body.source},
    )

    return DeliveryPublic(**updated)


@app.get(
    "/deliveries/{delivery_id}/history",
    tags=["deliveries"],
    summary="Get delivery history (status timeline + location pings)",
    response_model=DeliveryHistoryResponse,
)
async def delivery_history(
    delivery_id: UUID,
    session: AsyncSession = Depends(get_db_session),
    user: CurrentUser = Depends(get_current_user),
    limit_status_events: int = Query(100, ge=1, le=500, description="Max status events to return"),
    limit_location_pings: int = Query(200, ge=1, le=1000, description="Max location pings to return"),
) -> DeliveryHistoryResponse:
    """Get status timeline and location history for a delivery if authorized."""
    dres = await session.execute(text("SELECT * FROM deliveries WHERE id = :id"), {"id": str(delivery_id)})
    delivery = dres.mappings().first()
    if not delivery:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Delivery not found")
    _ensure_delivery_access(user, delivery)

    sres = await session.execute(
        text(
            """
            SELECT *
            FROM delivery_status_events
            WHERE delivery_id = :id
            ORDER BY occurred_at DESC
            LIMIT :lim
            """
        ),
        {"id": str(delivery_id), "lim": limit_status_events},
    )
    lres = await session.execute(
        text(
            """
            SELECT *
            FROM location_pings
            WHERE delivery_id = :id
            ORDER BY pinged_at DESC
            LIMIT :lim
            """
        ),
        {"id": str(delivery_id), "lim": limit_location_pings},
    )

    return DeliveryHistoryResponse(
        delivery=DeliveryPublic(**delivery),
        status_events=[DeliveryStatusEventPublic(**r) for r in sres.mappings().all()],
        location_pings=[LocationPingPublic(**r) for r in lres.mappings().all()],
    )


# -----------------------
# Admin endpoints
# -----------------------

@app.get(
    "/admin/users",
    tags=["admin"],
    summary="Admin: list users",
    response_model=list[UserPublic],
)
async def admin_list_users(session: AsyncSession = Depends(get_db_session), _: CurrentUser = Depends(require_admin)) -> list[UserPublic]:
    """Admin: list all users."""
    res = await session.execute(text("SELECT id, email, full_name, role, is_active, created_at, updated_at FROM users ORDER BY created_at DESC"))
    return [UserPublic(**r) for r in res.mappings().all()]


@app.post(
    "/admin/users",
    tags=["admin"],
    summary="Admin: create user",
    response_model=UserPublic,
    status_code=status.HTTP_201_CREATED,
)
async def admin_create_user(
    body: UserCreateAdmin,
    session: AsyncSession = Depends(get_db_session),
    _: CurrentUser = Depends(require_admin),
) -> UserPublic:
    """Admin: create a user with role and activation."""
    pw_hash = hash_password(body.password)
    try:
        res = await session.execute(
            text(
                """
                INSERT INTO users (email, password_hash, full_name, role, is_active)
                VALUES (:email, :password_hash, :full_name, :role, :is_active)
                RETURNING id, email, full_name, role, is_active, created_at, updated_at
                """
            ),
            {
                "email": str(body.email).lower(),
                "password_hash": pw_hash,
                "full_name": body.full_name,
                "role": body.role,
                "is_active": body.is_active,
            },
        )
        await session.commit()
    except Exception:
        await session.rollback()
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Email already exists")

    return UserPublic(**res.mappings().one())


@app.patch(
    "/admin/users/{user_id}",
    tags=["admin"],
    summary="Admin: update user",
    response_model=UserPublic,
)
async def admin_update_user(
    user_id: UUID,
    body: UserUpdateAdmin,
    session: AsyncSession = Depends(get_db_session),
    _: CurrentUser = Depends(require_admin),
) -> UserPublic:
    """Admin: update user fields and optionally reset password."""
    # Build dynamic update
    fields = {}
    if body.full_name is not None:
        fields["full_name"] = body.full_name
    if body.role is not None:
        fields["role"] = body.role
    if body.is_active is not None:
        fields["is_active"] = body.is_active
    if body.password is not None:
        fields["password_hash"] = hash_password(body.password)

    if not fields:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="No updates provided")

    set_clause = ", ".join([f"{k} = :{k}" for k in fields.keys()])
    fields["id"] = str(user_id)

    await session.execute(text(f"UPDATE users SET {set_clause} WHERE id = :id"), fields)
    await session.commit()

    res = await session.execute(text("SELECT id, email, full_name, role, is_active, created_at, updated_at FROM users WHERE id = :id"), {"id": str(user_id)})
    row = res.mappings().first()
    if not row:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
    return UserPublic(**row)


@app.get(
    "/admin/deliveries",
    tags=["admin"],
    summary="Admin: list deliveries",
    response_model=list[DeliveryPublic],
)
async def admin_list_deliveries(
    session: AsyncSession = Depends(get_db_session),
    _: CurrentUser = Depends(require_admin),
) -> list[DeliveryPublic]:
    """Admin: list all deliveries."""
    res = await session.execute(text("SELECT * FROM deliveries ORDER BY updated_at DESC"))
    return [DeliveryPublic(**r) for r in res.mappings().all()]


@app.post(
    "/admin/deliveries",
    tags=["admin"],
    summary="Admin: create delivery",
    response_model=DeliveryPublic,
    status_code=status.HTTP_201_CREATED,
)
async def admin_create_delivery(
    body: DeliveryCreate,
    session: AsyncSession = Depends(get_db_session),
    _: CurrentUser = Depends(require_admin),
) -> DeliveryPublic:
    """Admin: create a delivery."""
    status_value = body.current_status or "created"
    try:
        res = await session.execute(
            text(
                """
                INSERT INTO deliveries (
                  tracking_number, user_id, assigned_driver_id,
                  carrier, title, description, origin_address, destination_address,
                  scheduled_delivery_date, current_status
                )
                VALUES (
                  :tracking_number, :user_id, :assigned_driver_id,
                  :carrier, :title, :description, :origin_address, :destination_address,
                  :scheduled_delivery_date, :current_status
                )
                RETURNING *
                """
            ),
            {
                "tracking_number": body.tracking_number,
                "user_id": str(body.user_id),
                "assigned_driver_id": str(body.assigned_driver_id) if body.assigned_driver_id else None,
                "carrier": body.carrier,
                "title": body.title,
                "description": body.description,
                "origin_address": body.origin_address,
                "destination_address": body.destination_address,
                "scheduled_delivery_date": body.scheduled_delivery_date,
                "current_status": status_value,
            },
        )
        created = res.mappings().one()

        # Create initial status event
        await session.execute(
            text(
                """
                INSERT INTO delivery_status_events (delivery_id, status, note, created_by_user_id)
                VALUES (:delivery_id, :status, :note, :created_by_user_id)
                """
            ),
            {
                "delivery_id": str(created["id"]),
                "status": status_value,
                "note": "Created",
                "created_by_user_id": None,
            },
        )
        await session.commit()
    except Exception:
        await session.rollback()
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Tracking number already exists")

    return DeliveryPublic(**created)


@app.patch(
    "/admin/deliveries/{delivery_id}",
    tags=["admin"],
    summary="Admin: update delivery metadata (not status/location)",
    response_model=DeliveryPublic,
)
async def admin_update_delivery(
    delivery_id: UUID,
    body: DeliveryUpdate,
    session: AsyncSession = Depends(get_db_session),
    _: CurrentUser = Depends(require_admin),
) -> DeliveryPublic:
    """Admin: update delivery fields (excluding status/location updates)."""
    fields: dict[str, Any] = {}
    if body.assigned_driver_id is not None:
        fields["assigned_driver_id"] = str(body.assigned_driver_id)
    if body.carrier is not None:
        fields["carrier"] = body.carrier
    if body.title is not None:
        fields["title"] = body.title
    if body.description is not None:
        fields["description"] = body.description
    if body.origin_address is not None:
        fields["origin_address"] = body.origin_address
    if body.destination_address is not None:
        fields["destination_address"] = body.destination_address
    if body.scheduled_delivery_date is not None:
        fields["scheduled_delivery_date"] = body.scheduled_delivery_date

    if not fields:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="No updates provided")

    set_clause = ", ".join([f"{k} = :{k}" for k in fields.keys()])
    fields["id"] = str(delivery_id)

    await session.execute(text(f"UPDATE deliveries SET {set_clause} WHERE id = :id"), fields)
    await session.commit()

    res = await session.execute(text("SELECT * FROM deliveries WHERE id = :id"), {"id": str(delivery_id)})
    row = res.mappings().first()
    if not row:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Delivery not found")
    return DeliveryPublic(**row)


@app.delete(
    "/admin/deliveries/{delivery_id}",
    tags=["admin"],
    summary="Admin: delete delivery",
)
async def admin_delete_delivery(
    delivery_id: UUID,
    session: AsyncSession = Depends(get_db_session),
    _: CurrentUser = Depends(require_admin),
) -> dict[str, Any]:
    """Admin: delete a delivery (cascades status events and pings)."""
    res = await session.execute(text("DELETE FROM deliveries WHERE id = :id RETURNING id"), {"id": str(delivery_id)})
    deleted = res.mappings().first()
    await session.commit()
    if not deleted:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Delivery not found")
    return {"ok": True, "deleted_id": str(deleted["id"])}


# -----------------------
# Realtime (WebSocket)
# -----------------------

@app.websocket("/realtime/ws")
async def realtime_ws(websocket: WebSocket) -> None:
    """
    WebSocket for realtime updates.

    Authentication:
      - Pass access token as query parameter: /realtime/ws?token=<JWT_ACCESS_TOKEN>

    Subscribe:
      {"action":"subscribe","delivery_id":"<uuid>"}

    Unsubscribe:
      {"action":"unsubscribe","delivery_id":"<uuid>"}
    """
    token = websocket.query_params.get("token")
    if not token:
        await websocket.close(code=4401)
        return

    # Validate token by calling a minimal decode endpoint logic using DB.
    # We don't load full user object here; we just need role/sub.
    from src.api.security import decode_and_validate_token  # local import

    try:
        payload = decode_and_validate_token(token, expected_type="access")
        user_id = UUID(str(payload["sub"]))
        role = str(payload.get("role"))
    except Exception:
        await websocket.close(code=4401)
        return

    await websocket.accept()
    try:
        while True:
            msg = await websocket.receive_json()
            action = msg.get("action")
            delivery_id_raw = msg.get("delivery_id")
            if action not in ("subscribe", "unsubscribe"):
                await websocket.send_json({"error": "Unknown action"})
                continue
            try:
                delivery_id = UUID(str(delivery_id_raw))
            except Exception:
                await websocket.send_json({"error": "Invalid delivery_id"})
                continue

            # Authorize subscription: must be admin, owner, or assigned driver.
            # We check from DB on each subscription request for correctness.
            async with get_db_session().__anext__() as session:  # type: ignore[misc]
                res = await session.execute(text("SELECT user_id, assigned_driver_id FROM deliveries WHERE id = :id"), {"id": str(delivery_id)})
                delivery = res.mappings().first()
                if not delivery:
                    await websocket.send_json({"error": "Delivery not found"})
                    continue
                if role != "admin":
                    if str(delivery["user_id"]) != str(user_id) and str(delivery.get("assigned_driver_id") or "") != str(user_id):
                        await websocket.send_json({"error": "Not authorized for this delivery"})
                        continue

            if action == "subscribe":
                await realtime_hub.subscribe(websocket, delivery_id)
                await websocket.send_json({"ok": True, "subscribed": str(delivery_id)})
            else:
                # For simplicity, just remove all and re-add others (unsubscribe_all is O(n) but small here).
                await realtime_hub.unsubscribe_all(websocket)
                await websocket.send_json({"ok": True, "unsubscribed": str(delivery_id)})

    except WebSocketDisconnect:
        await realtime_hub.unsubscribe_all(websocket)
    except Exception:
        await realtime_hub.unsubscribe_all(websocket)
        try:
            await websocket.close(code=1011)
        except Exception:
            pass
