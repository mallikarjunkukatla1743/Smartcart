# 🛒 SmartCart - Modern E-Commerce Platform

SmartCart is a full-featured, modern e-commerce web application built with Python and Flask. It provides a seamless shopping experience for users and a robust management system for admins.

## ✨ Key Features

### 👤 User Features
- **Modern UI/UX**: Clean, responsive design with smooth transitions.
- **Product Catalog**: Browse products by categories with search and filtering.
- **Shopping Cart**: Dynamic cart management (add, remove, update quantities).
- **Secure Authentication**: User registration and login with encrypted passwords.
- **Order Management**: Track order history and view detailed invoices.
- **PDF Invoices**: Automatically generated PDF invoices sent via email.
- **Payment Integration**: Secure checkout with Razorpay and mock payment support.

### 🛡️ Admin Features
- **Admin Dashboard**: Real-time sales statistics, revenue tracking, and customer overview.
- **Inventory Management**: Full CRUD (Create, Read, Update, Delete) operations for products.
- **Order Processing**: View and manage all platform orders.
- **Role Isolation**: Secure multi-admin session management preventing data leakage.
- **Advanced Guard**: Session-based security with IP tracking and login logs.

## 🛠️ Technology Stack
- **Backend**: Python, Flask
- **Database**: SQLite (Migrated from MySQL for portability)
- **Frontend**: HTML5, CSS3 (Vanilla), JavaScript
- **Payments**: Razorpay API
- **Email**: Flask-Mail (SMTP Integration)
- **PDF Generation**: xhtml2pdf
- **Security**: Bcrypt, Python-Dotenv

## 🚀 Setup Instructions

### 1. Clone the repository
```bash
git clone https://github.com/YOUR_USERNAME/smartcart.git
cd smartcart
```

### 2. Set up Virtual Environment
```bash
python -m venv venv
# On Windows:
.\venv\Scripts\activate
# On Mac/Linux:
source venv/bin/activate
```

### 3. Install Dependencies
```bash
pip install -r requirements.txt
```

### 4. Configure Environment Variables
Create a `.env` file in the root directory and fill in your details (refer to `.env.example`):
```env
SECRET_KEY=your_secret_key
MAIL_SERVER=smtp.gmail.com
MAIL_PORT=587
MAIL_USE_TLS=True
MAIL_USERNAME=your_email@gmail.com
MAIL_PASSWORD=your_app_password
RAZORPAY_KEY_ID=your_razorpay_id
RAZORPAY_KEY_SECRET=your_razorpay_secret
DATABASE_URL=smartcart.db
```

### 5. Run the Application
```bash
python app.py
```
Open `http://127.0.0.1:5000` in your browser.

## 🔒 Security Note
The `.env` file and `smartcart.db` are ignored by Git to protect your sensitive credentials and local data. Always use the provided `.env.example` to set up new environments.

---
Built with ❤️ by [Your Name]
