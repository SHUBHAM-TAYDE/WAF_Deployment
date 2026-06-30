from fastapi import APIRouter, Depends, HTTPException, status, Request
from fastapi.security import OAuth2PasswordRequestForm
from pydantic import BaseModel
import pyotp
import qrcode
import io
import base64

from app.services.auth import verify_password, create_access_token, get_current_user, TokenData
from app.services.settings_manager import settings_manager

router = APIRouter()


class Token(BaseModel):
    access_token: str
    token_type: str


class MfaSetupResponse(BaseModel):
    secret: str
    qr_code: str
    provisioning_uri: str


class MfaVerifyRequest(BaseModel):
    code: str
    secret: str


class MfaStatusResponse(BaseModel):
    enabled: bool


@router.post("/login", response_model=Token)
async def login_for_access_token(
    request: Request,
    form_data: OAuth2PasswordRequestForm = Depends()
):
    username = form_data.username
    password = form_data.password

    if username == "admin":
        current_hash = settings_manager.get_password_hash()
        role = "admin"
    elif username == "analyst":
        current_hash = settings_manager.get_analyst_password_hash()
        role = "analyst"
    else:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )

    if not verify_password(password, current_hash):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # Check if MFA is enabled
    mfa_settings = settings_manager.get_mfa_settings()
    mfa_enabled = mfa_settings["mfa_enabled"] if role == "admin" else mfa_settings["analyst_mfa_enabled"]
    mfa_secret = mfa_settings["mfa_secret"] if role == "admin" else mfa_settings["analyst_mfa_secret"]

    if mfa_enabled:
        form_params = await request.form()
        otp_code = form_params.get("otp_code") or form_params.get("otp") or ""
        
        if not otp_code:
            # Tell the client that MFA code is required to proceed
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="MFA_REQUIRED"
            )
            
        totp = pyotp.TOTP(mfa_secret)
        if not totp.verify(otp_code):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="INVALID_MFA_CODE"
            )

    access_token = create_access_token(data={"sub": username, "role": role})
    return {"access_token": access_token, "token_type": "bearer"}


@router.get("/mfa/status", response_model=MfaStatusResponse)
async def mfa_status(current_user: TokenData = Depends(get_current_user)):
    username = current_user.username
    mfa_settings = settings_manager.get_mfa_settings()
    enabled = mfa_settings["mfa_enabled"] if username == "admin" else mfa_settings["analyst_mfa_enabled"]
    return {"enabled": enabled}


@router.get("/mfa/setup", response_model=MfaSetupResponse)
async def mfa_setup(current_user: TokenData = Depends(get_current_user)):
    username = current_user.username
    # Generate temporary secret
    secret = pyotp.random_base32()
    totp = pyotp.TOTP(secret)
    provisioning_uri = totp.provisioning_uri(
        name=f"{username}@cybersentinel",
        issuer_name="CyberSentinel WAF"
    )
    
    # Generate QR Code PNG image
    qr = qrcode.QRCode(version=1, box_size=4, border=4)
    qr.add_data(provisioning_uri)
    qr.make(fit=True)
    img = qr.make_image(fill_color="black", back_color="white")
    
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    qr_base64 = "data:image/png;base64," + base64.b64encode(buf.getvalue()).decode("utf-8")
    
    return {
        "secret": secret,
        "qr_code": qr_base64,
        "provisioning_uri": provisioning_uri
    }


@router.post("/mfa/enable")
async def mfa_enable(payload: MfaVerifyRequest, current_user: TokenData = Depends(get_current_user)):
    username = current_user.username
    totp = pyotp.TOTP(payload.secret)
    if not totp.verify(payload.code):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid verification code"
        )
        
    mfa_settings = settings_manager.get_mfa_settings()
    if username == "admin":
        mfa_settings["mfa_enabled"] = True
        mfa_settings["mfa_secret"] = payload.secret
    else:
        mfa_settings["analyst_mfa_enabled"] = True
        mfa_settings["analyst_mfa_secret"] = payload.secret
        
    settings_manager.update_mfa_settings(mfa_settings)
    return {"message": "MFA enabled successfully"}


@router.post("/mfa/disable")
async def mfa_disable(current_user: TokenData = Depends(get_current_user)):
    username = current_user.username
    mfa_settings = settings_manager.get_mfa_settings()
    if username == "admin":
        mfa_settings["mfa_enabled"] = False
        mfa_settings["mfa_secret"] = ""
    else:
        mfa_settings["analyst_mfa_enabled"] = False
        mfa_settings["analyst_mfa_secret"] = ""
        
    settings_manager.update_mfa_settings(mfa_settings)
    return {"message": "MFA disabled successfully"}
