import os

from fastapi import (
    Depends,
    FastAPI,
    Form,
    Request,
)
from fastapi.responses import (
    HTMLResponse,
    RedirectResponse,
)
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session

from .auth import (
    create_access_token,
    generate_reset_token,
    hash_password,
    hash_reset_token,
    reset_token_expiry,
    verify_password,
)
from .database import Base, engine, get_db
from .dependencies import get_current_user
from .email import send_reset_email
from .models import User


Base.metadata.create_all(bind=engine)

app = FastAPI(
    title="Auth App",
    version="2.0.0",
)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

app.mount(
    "/static",
    StaticFiles(directory=os.path.join(BASE_DIR, "static")),
    name="static",
)

templates = Jinja2Templates(
    directory=os.path.join(BASE_DIR, "templates")
)

COOKIE_SECURE = (
    os.getenv(
        "COOKIE_SECURE",
        "true",
    ).lower()
    == "true"
)

APP_URL = os.getenv(
    "APP_URL",
    "http://127.0.0.1:8000",
)


def render(
    request: Request,
    template: str,
    **context,
):
    return templates.TemplateResponse(
        request=request,
        name=template,
        context=context,
    )


# =========================
# LANDING PAGE
# =========================

@app.get(
    "/",
    response_class=HTMLResponse,
)
def landing(request: Request):
    return render(
        request,
        "landing.html",
    )


# =========================
# REGISTER
# =========================

@app.get(
    "/register",
    response_class=HTMLResponse,
)
def register_page(request: Request):
    return render(
        request,
        "register.html",
    )


@app.post("/register")
def register(
    request: Request,
    username: str = Form(...),
    email: str = Form(...),
    password: str = Form(...),
    confirm_password: str = Form(...),
    db: Session = Depends(get_db),
):
    username = username.strip()
    email = email.strip().lower()

    if password != confirm_password:
        return render(
            request,
            "register.html",
            error="Passwords do not match.",
        )

    if len(password) < 8:
        return render(
            request,
            "register.html",
            error="Password must be at least 8 characters.",
        )

    existing = (
        db.query(User)
        .filter(
            (User.email == email)
            | (User.username == username)
        )
        .first()
    )

    if existing:
        return render(
            request,
            "register.html",
            error="Username or email already exists.",
        )

    user = User(
        username=username,
        email=email,
        password_hash=hash_password(
            password
        ),
    )

    db.add(user)
    db.commit()

    return RedirectResponse(
        "/login?registered=1",
        status_code=303,
    )


# =========================
# LOGIN
# =========================

@app.get(
    "/login",
    response_class=HTMLResponse,
)
def login_page(request: Request):
    return render(
        request,
        "login.html",
        registered=request.query_params.get(
            "registered"
        ),
    )


@app.post("/login")
def login(
    request: Request,
    email: str = Form(...),
    password: str = Form(...),
    db: Session = Depends(get_db),
):
    email = email.strip().lower()

    user = (
        db.query(User)
        .filter(User.email == email)
        .first()
    )

    if (
        not user
        or not user.is_active
        or not verify_password(
            password,
            user.password_hash,
        )
    ):
        return render(
            request,
            "login.html",
            error="Invalid email or password.",
        )

    token = create_access_token(
        user.id
    )

    response = RedirectResponse(
        "/dashboard",
        status_code=303,
    )

    response.set_cookie(
        "access_token",
        token,
        httponly=True,
        secure=COOKIE_SECURE,
        samesite="lax",
        max_age=3600,
    )

    return response


# =========================
# LOGOUT
# =========================

@app.post("/logout")
def logout():
    response = RedirectResponse(
        "/",
        status_code=303,
    )

    response.delete_cookie(
        "access_token"
    )

    return response


# =========================
# DASHBOARD
# =========================

@app.get(
    "/dashboard",
    response_class=HTMLResponse,
)
def dashboard(
    request: Request,
    user: User = Depends(get_current_user),
):
    return render(
        request,
        "dashboard.html",
        user=user,
    )


# =========================
# PROFILE
# =========================

@app.get(
    "/profile",
    response_class=HTMLResponse,
)
def profile(
    request: Request,
    user: User = Depends(get_current_user),
):
    return render(
        request,
        "profile.html",
        user=user,
    )


# =========================
# EDIT PROFILE
# =========================

@app.get(
    "/profile/edit",
    response_class=HTMLResponse,
)
def edit_profile_page(
    request: Request,
    user: User = Depends(get_current_user),
):
    return render(
        request,
        "edit_profile.html",
        user=user,
    )


@app.post("/profile/edit")
def edit_profile(
    request: Request,
    full_name: str = Form(""),
    username: str = Form(...),
    bio: str = Form(""),
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    username = username.strip()

    existing = (
        db.query(User)
        .filter(
            User.username == username,
            User.id != user.id,
        )
        .first()
    )

    if existing:
        return render(
            request,
            "edit_profile.html",
            user=user,
            error="Username already taken.",
        )

    user.username = username
    user.full_name = full_name.strip()
    user.bio = bio.strip()

    db.commit()

    return RedirectResponse(
        "/profile?updated=1",
        status_code=303,
    )


# =========================
# CHANGE PASSWORD
# =========================

@app.get(
    "/profile/change-password",
    response_class=HTMLResponse,
)
def change_password_page(
    request: Request,
    user: User = Depends(get_current_user),
):
    return render(
        request,
        "change_password.html",
        user=user,
    )


@app.post("/profile/change-password")
def change_password(
    request: Request,
    current_password: str = Form(...),
    new_password: str = Form(...),
    confirm_password: str = Form(...),
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    if not verify_password(
        current_password,
        user.password_hash,
    ):
        return render(
            request,
            "change_password.html",
            user=user,
            error="Current password is incorrect.",
        )

    if len(new_password) < 8:
        return render(
            request,
            "change_password.html",
            user=user,
            error="New password must be at least 8 characters.",
        )

    if new_password != confirm_password:
        return render(
            request,
            "change_password.html",
            user=user,
            error="Passwords do not match.",
        )

    user.password_hash = hash_password(
        new_password
    )

    db.commit()

    response = RedirectResponse(
        "/login?password_changed=1",
        status_code=303,
    )

    response.delete_cookie(
        "access_token"
    )

    return response


# =========================
# FORGOT PASSWORD
# =========================

@app.get(
    "/forgot-password",
    response_class=HTMLResponse,
)
def forgot_password_page(
    request: Request,
):
    return render(
        request,
        "forgot_password.html",
    )


@app.post("/forgot-password")
def forgot_password(
    request: Request,
    email: str = Form(...),
    db: Session = Depends(get_db),
):
    email = email.strip().lower()

    user = (
        db.query(User)
        .filter(User.email == email)
        .first()
    )

    if user:
        token = generate_reset_token()

        user.reset_token_hash = (
            hash_reset_token(token)
        )

        user.reset_token_expires = (
            reset_token_expiry()
        )

        db.commit()

        reset_url = (
            f"{APP_URL}/reset-password/{token}"
        )

        send_reset_email(
            user.email,
            reset_url,
        )

    # Same response whether user exists or not
    return render(
        request,
        "forgot_password.html",
        success=(
            "If an account exists for that email, "
            "a password reset link has been sent."
        ),
    )


# =========================
# RESET PASSWORD
# =========================

@app.get(
    "/reset-password/{token}",
    response_class=HTMLResponse,
)
def reset_password_page(
    request: Request,
    token: str,
    db: Session = Depends(get_db),
):
    token_hash = hash_reset_token(
        token
    )

    user = (
        db.query(User)
        .filter(
            User.reset_token_hash
            == token_hash
        )
        .first()
    )

    if (
        not user
        or not user.reset_token_expires
        or user.reset_token_expires
        < __import__(
            "datetime"
        ).datetime.now(
            __import__(
                "datetime"
            ).timezone.utc
        )
    ):
        return render(
            request,
            "reset_password.html",
            error="This reset link is invalid or expired.",
            token=None,
        )

    return render(
        request,
        "reset_password.html",
        token=token,
    )


@app.post(
    "/reset-password/{token}"
)
def reset_password(
    request: Request,
    token: str,
    password: str = Form(...),
    confirm_password: str = Form(...),
    db: Session = Depends(get_db),
):
    token_hash = hash_reset_token(
        token
    )

    user = (
        db.query(User)
        .filter(
            User.reset_token_hash
            == token_hash
        )
        .first()
    )

    from datetime import datetime, timezone

    if (
        not user
        or not user.reset_token_expires
        or user.reset_token_expires
        < datetime.now(timezone.utc)
    ):
        return render(
            request,
            "reset_password.html",
            error="This reset link is invalid or expired.",
            token=None,
        )

    if len(password) < 8:
        return render(
            request,
            "reset_password.html",
            error="Password must be at least 8 characters.",
            token=token,
        )

    if password != confirm_password:
        return render(
            request,
            "reset_password.html",
            error="Passwords do not match.",
            token=token,
        )

    user.password_hash = hash_password(
        password
    )

    user.reset_token_hash = None
    user.reset_token_expires = None

    db.commit()

    return RedirectResponse(
        "/login?reset=1",
        status_code=303,
    )


# =========================
# DELETE ACCOUNT
# =========================

@app.get(
    "/account/delete",
    response_class=HTMLResponse,
)
def delete_account_page(
    request: Request,
    user: User = Depends(get_current_user),
):
    return render(
        request,
        "delete_account.html",
        user=user,
    )


@app.post("/account/delete")
def delete_account(
    request: Request,
    password: str = Form(...),
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    if not verify_password(
        password,
        user.password_hash,
    ):
        return render(
            request,
            "delete_account.html",
            user=user,
            error="Incorrect password.",
        )

    db.delete(user)
    db.commit()

    response = RedirectResponse(
        "/?deleted=1",
        status_code=303,
    )

    response.delete_cookie(
        "access_token"
    )

    return response