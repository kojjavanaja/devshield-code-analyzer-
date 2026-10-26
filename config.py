import os
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
def env(name: str, default: str) -> str:
    value = os.getenv(name)
    if value is not None: return value
    envfile = ROOT / ".env"
    if envfile.exists():
        for line in envfile.read_text(encoding="utf-8").splitlines():
            if line.strip() and not line.strip().startswith("#") and "=" in line:
                k, v = line.split("=", 1)
                if k.strip() == name: return v.strip().strip('"').strip("'")
    return default
DATABASE_URL = env("DATABASE_URL", "sqlite:///./devshield-local.db")
SECRET_KEY = env("SECRET_KEY", "unsafe-development-secret-change-before-use")
APP_NAME = env("APP_NAME", "DevShield API")
CORS_ORIGINS = [x.strip() for x in env("CORS_ORIGINS", "http://localhost:5173").split(",") if x.strip()]
ACCESS_TOKEN_MINUTES = int(env("ACCESS_TOKEN_MINUTES", "30"))
UPLOAD_DIR = Path(env("UPLOAD_DIR", str(ROOT / "storage")))
