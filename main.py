import uvicorn

from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from typing import List, Dict
from hashlib import sha256
from fastapi.responses import RedirectResponse
from werkzeug.security import generate_password_hash, check_password_hash

app = FastAPI(debug=True)

security = HTTPBasic()

users_db: dict = {
    "Oleh": {
        "username": "user1",
        "hashed_password": generate_password_hash("secret"),
        "role": "user",
    },
    "Mike": {
        "username": "admin1",
        "hashed_password": generate_password_hash("secret2"),
        "role": "admin",
    },
}


@app.get("/", include_in_schema=False)
def read_root():
    return RedirectResponse("/docs")


def get_user_by_username(username: str):
    for user_data in users_db.values():
        if user_data["username"] == username:
            return user_data
    return None


@app.get("/secure-data/")
def read_secure_data(credentials: HTTPBasicCredentials = Depends(security)):
    user = get_user_by_username(credentials.username)
    role = user["role"]
    if not user or not check_password_hash(user["hashed_password"], credentials.password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid username or password",
            headers={"WWW-Authenticate": "Basic"},
        )
    return {"username": credentials.username,
            "password": credentials.password,
            "role": role}


@app.get("/admin/users/")
def get_users(credentials: HTTPBasicCredentials = Depends(security)):
    user = get_user_by_username(credentials.username)

    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials",
            headers={"WWW-Authenticate": "Basic"},
        )

    if not check_password_hash(user["hashed_password"], credentials.password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials",
            headers={"WWW-Authenticate": "Basic"},
        )

    if user["role"] != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Only for VIP.",
        )

    return {"users": [u["username"] for u in users_db.values()]}


if __name__ == "__main__":
    uvicorn.run(f"{__name__}:app", reload=True)
