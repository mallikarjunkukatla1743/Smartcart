# config.py
# ------------------------------------
import os
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

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
MAIL_DEFAULT_SENDER = os.getenv("MAIL_DEFAULT_SENDER")

# Razorpay Payment 
RAZORPAY_KEY_ID = os.getenv("RAZORPAY_KEY_ID")
RAZORPAY_KEY_SECRET = os.getenv("RAZORPAY_KEY_SECRET")
