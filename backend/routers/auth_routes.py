import platform

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel

from auth import is_strong_password, login_user, register_user
from database import (
    check_lockout,
    get_admin_username,
    log_login_device,
    record_failed_login,
    request_unfreeze,
    reset_failed_logins,
)
from logger import log_action
from secure_messaging import generate_keys

from backend.core import create_token, current_user, load_user, public_user

router = APIRouter(prefix="/api/auth", tags=["auth"])


class LoginBody(BaseModel):
    username: str
    password: str


class RegisterBody(BaseModel):
    username: str
    password: str
    personal_key: str
    pin: str


@router.post("/login")
def login(body: LoginBody, request: Request):
    username = body.username.strip()
    locked, minutes = check_lockout(username)
    if locked:
        log_action(username, "Login attempt while locked out", "WARNING")
        raise HTTPException(423, f"Account locked after too many failed attempts. Try again in {minutes} minute(s).")

    if not login_user(username, body.password):
        if record_failed_login(username):
            log_action(username, "Account locked after 5 failed login attempts", "ALERT")
            raise HTTPException(423, "Too many failed attempts. Account locked for 30 minutes.")
        log_action(username, "Failed login attempt", "WARNING")
        raise HTTPException(401, "Invalid username or password")

    reset_failed_logins(username)
    ip = request.client.host if request.client else "unknown"
    agent = request.headers.get("user-agent", f"API client on {platform.system()}")
    log_login_device(username, ip, agent[:200])
    log_action(username, f"Logged in from {ip}", "INFO")
    return {"token": create_token(username), "user": public_user(load_user(username))}


@router.post("/register", status_code=201)
def register(body: RegisterBody):
    username = body.username.strip()
    admin_name = get_admin_username()
    if not username:
        raise HTTPException(422, "Username is required.")
    if admin_name and username.lower() == admin_name.lower():
        raise HTTPException(422, "That username is reserved. Please choose a different username.")
    if not body.pin.isdigit() or len(body.pin) != 4:
        raise HTTPException(422, "PIN must be exactly 4 digits.")
    if not is_strong_password(body.password):
        raise HTTPException(422, "Password must be 8+ characters with upper and lower case, a number and a symbol.")
    if not body.personal_key:
        raise HTTPException(422, "Personal encryption key is required.")

    private_key, public_key = generate_keys()
    if not register_user(username, body.password, body.personal_key, "client", body.pin, public_key, private_key):
        raise HTTPException(409, "Username already exists. Please choose another.")
    log_action(username, "Registered new client account", "INFO")
    return {"ok": True}


@router.get("/me")
def me(user=Depends(current_user)):
    return public_user(user)


@router.post("/unfreeze-request")
def unfreeze_request(user=Depends(current_user)):
    request_unfreeze(user["username"])
    log_action(user["username"], "Requested account unfreeze", "INFO")
    return {"ok": True}
