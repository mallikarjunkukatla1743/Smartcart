# config.py
# ------------------------------------
import os
from dotenv import load_dotenv

# Load environment variables from absolute path
BASE_DIR = os.path.abspath(os.path.dirname(__file__))
env_path = os.path.join(BASE_DIR, ".env")
if os.path.exists(env_path):
    print(f"Config: .env file found at {env_path}, loading...")
    load_dotenv(env_path)
else:
    print(f"Config: NO .env file found at {env_path}. Using fallback environment variables.")


SECRET_KEY = os.getenv("SECRET_KEY", "abc123")

# Database Configuration (SQLite)
BASE_DIR = os.path.abspath(os.path.dirname(__file__))
DATABASE_URL = os.getenv("DATABASE_URL", os.path.join(BASE_DIR, "smartcart.db"))

# Email SMTP Settings
MAIL_SERVER = os.getenv("MAIL_SERVER", "smtp.gmail.com")
MAIL_PORT = int(os.getenv("MAIL_PORT", 587))
MAIL_USE_TLS = os.getenv("MAIL_USE_TLS", "True") == "True"
MAIL_USE_SSL = os.getenv("MAIL_USE_SSL", "False") == "True"
MAIL_USERNAME = os.getenv("MAIL_USERNAME")
MAIL_PASSWORD = os.getenv("MAIL_PASSWORD")
MAIL_DEFAULT_SENDER = os.getenv("MAIL_DEFAULT_SENDER", os.getenv("MAIL_USERNAME"))

# Razorpay Payment 
RAZORPAY_KEY_ID = os.getenv("RAZORPAY_KEY_ID", "").strip()
RAZORPAY_KEY_SECRET = os.getenv("RAZORPAY_KEY_SECRET", "").strip()
UPI_ID = os.getenv("UPI_ID", "mallikarjun@upi") # Default placeholder


# Configuration debug (will show in PythonAnywhere server logs)
print(f"DEBUG: DATABASE_URL is set to {DATABASE_URL}")
print(f"DEBUG: MAIL_USERNAME: {'SET' if MAIL_USERNAME else 'NOT SET'}")
print(f"DEBUG: RAZORPAY_KEY_ID: {'SET' if RAZORPAY_KEY_ID else 'NOT SET'}")

