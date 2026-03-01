from flask import Flask, render_template, request, redirect, session, flash, jsonify, make_response, current_app, url_for, Blueprint
from flask_mail import Mail, Message
import sqlite3
import bcrypt
import random
import config
import os
import traceback
from io import BytesIO
from xhtml2pdf import pisa
from werkzeug.utils import secure_filename
import uuid
from datetime import datetime

app = Flask(__name__)
app.secret_key = config.SECRET_KEY

def format_datetime(value, format_str='%d %b, %Y'):
    if not value: return "N/A"
    if isinstance(value, str):
        try:
            # SQLite stores dates as strings, e.g., '2026-02-24T22:45:39'
            value = datetime.fromisoformat(value.replace('Z', '+00:00'))
        except: return value
    return value.strftime(format_str)

app.jinja_env.filters['strftime'] = format_datetime
app.config['SESSION_COOKIE_NAME'] = 'smartcart_v3_session'
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'

# Prevent browser caching of sensitive pages (fixes admin session refresh issues)
@app.after_request
def add_header(response):
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Pragma"] = "no-cache"
    response.headers["Expires"] = "0"
    return response

# ---------------------------------------------------------
# DATABASE & EXTENSIONS CONFIGURATION
# ---------------------------------------------------------
app.config['MAIL_SERVER'] = config.MAIL_SERVER
app.config['MAIL_PORT'] = config.MAIL_PORT
app.config['MAIL_USE_TLS'] = config.MAIL_USE_TLS
app.config['MAIL_USE_SSL'] = getattr(config, 'MAIL_USE_SSL', False)
app.config['MAIL_USERNAME'] = config.MAIL_USERNAME
app.config['MAIL_PASSWORD'] = config.MAIL_PASSWORD
app.config['MAIL_DEFAULT_SENDER'] = config.MAIL_DEFAULT_SENDER

mail = Mail(app)

# Re-init Razorpay with cleaned strings
import razorpay
razorpay_client = razorpay.Client(
    auth=(config.RAZORPAY_KEY_ID, config.RAZORPAY_KEY_SECRET)
)

def get_db_connection():
    # Adding timeout and isolation level to prevent "Database Locked" errors on PythonAnywhere
    conn = sqlite3.connect(config.DATABASE_URL, timeout=10, detect_types=sqlite3.PARSE_DECLTYPES | sqlite3.PARSE_COLNAMES)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    """Initializes the database and performs repairs/migrations for missing columns."""
    conn = get_db_connection()
    # Ensure foreign keys are enabled
    conn.execute("PRAGMA foreign_keys = ON")
    cursor = conn.cursor()
    
    # helper for migrations
    def add_column_if_missing(table, column, definition):
        try:
            cursor.execute(f"ALTER TABLE {table} ADD COLUMN {column} {definition}")
            print(f"Migration: Added {column} to {table}")
        except sqlite3.OperationalError:
            pass # Column already exists

    # 1. Admin Table
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS admin (
        admin_id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT,
        email TEXT UNIQUE,
        password TEXT,
        profile_image TEXT,
        status TEXT DEFAULT 'pending',
        is_super INTEGER DEFAULT 0,
        deletion_requested INTEGER DEFAULT 0,
        last_login DATETIME,
        session_token TEXT,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )
    ''')
    add_column_if_missing('admin', 'status', "TEXT DEFAULT 'pending'")
    add_column_if_missing('admin', 'is_super', "INTEGER DEFAULT 0")
    add_column_if_missing('admin', 'deletion_requested', "INTEGER DEFAULT 0")
    add_column_if_missing('admin', 'session_token', "TEXT")

    # 2. Users Table
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS users (
        user_id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT,
        email TEXT UNIQUE,
        password TEXT,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )
    ''')
    add_column_if_missing('users', 'created_at', "DATETIME DEFAULT CURRENT_TIMESTAMP")

    # 3. Products Table
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS products (
        product_id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT,
        description TEXT,
        category TEXT,
        price REAL,
        stock INTEGER DEFAULT 0,
        image TEXT,
        admin_id INTEGER,
        is_active INTEGER DEFAULT 1,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (admin_id) REFERENCES admin (admin_id)
    )
    ''')
    add_column_if_missing('products', 'is_active', "INTEGER DEFAULT 1")
    add_column_if_missing('products', 'stock', "INTEGER DEFAULT 0")
    add_column_if_missing('products', 'created_at', "DATETIME DEFAULT CURRENT_TIMESTAMP")

    # 4. Orders Table
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS orders (
        order_id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        amount REAL,
        payment_status TEXT,
        razorpay_order_id TEXT,
        razorpay_payment_id TEXT,
        shipping_address TEXT,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users (user_id)
    )
    ''')

    # 5. Order Items Table
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS order_items (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        order_id INTEGER,
        product_id INTEGER,
        product_name TEXT,
        quantity INTEGER,
        price REAL,
        FOREIGN KEY (order_id) REFERENCES orders (order_id),
        FOREIGN KEY (product_id) REFERENCES products (product_id)
    )
    ''')

    # 6. Login Logs Table
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS login_logs (
        log_id INTEGER PRIMARY KEY AUTOINCREMENT,
        admin_id INTEGER,
        admin_name TEXT,
        login_time DATETIME,
        browser TEXT,
        ip_address TEXT,
        FOREIGN KEY (admin_id) REFERENCES admin (admin_id)
    )
    ''')

    # 7. Contact Messages Table
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS contact_messages (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT,
        email TEXT,
        subject TEXT,
        message TEXT,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )
    ''')

    # 8. User Addresses Table
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS user_addresses (
        address_id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        full_name TEXT,
        phone TEXT,
        address_line TEXT,
        city TEXT,
        state TEXT,
        pincode TEXT,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users (user_id)
    )
    ''')
    
    conn.commit()
    conn.close()
    print("Database initialized and verified.")


# ---------------------------------------------------------
# UTILS: PDF GENERATOR
# ---------------------------------------------------------
def generate_pdf(html):
    pdf = BytesIO()
    pisa_status = pisa.CreatePDF(html, dest=pdf)
    if pisa_status.err:
        return None
    pdf.seek(0)
    return pdf

def send_order_email(order_id):
    """Fetches order details, generates an invoice PDF, and emails it to the customer."""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        # Fetch order details along with buyer email
        cursor.execute("""
            SELECT o.*, u.email as user_email, u.name as user_name 
            FROM orders o 
            JOIN users u ON o.user_id = u.user_id 
            WHERE o.order_id = ?
        """, (order_id,))
        order = cursor.fetchone()
        
        if not order:
            cursor.close(); conn.close()
            return False
            
        cursor.execute("SELECT * FROM order_items WHERE order_id = ?", (order_id,))
        items = cursor.fetchall()
        cursor.close(); conn.close()

        # Generate HTML from template and convert to PDF
        html = render_template('user/invoice.html', order=order, items=items)
        pdf = generate_pdf(html)

        msg = Message(
            subject=f"Order Confirmed: #{order_id} - SmartCart",
            recipients=[order['user_email']],
            body=f"Hello {order['user_name']},\n\nYour payment of ₹{order['amount']} for Order #{order_id} has been successfully processed.\n\nPlease find your invoice attached to this email.\n\nThank you for shopping with us!\nSmartCart Team"
        )
        
        if pdf:
            msg.attach(f"invoice_{order_id}.pdf", "application/pdf", pdf.read())

        mail.send(msg)
        return True
    except Exception as e:
        print(f"CRITICAL: Failed to send order confirmation email: {e}")
        return False

# ---------------------------------------------------------
# FILE UPLOAD CONFIGURATION
# ---------------------------------------------------------
app.config['UPLOAD_FOLDER'] = 'static/uploads/product_images'
app.config['ADMIN_UPLOAD_FOLDER'] = 'static/uploads/admin_profiles'

if not os.path.exists(app.config['UPLOAD_FOLDER']):
    os.makedirs(app.config['UPLOAD_FOLDER'])
if not os.path.exists(app.config['ADMIN_UPLOAD_FOLDER']):
    os.makedirs(app.config['ADMIN_UPLOAD_FOLDER'])

# ---------------------------------------------------------
# BLUEPRINT DEFINITIONS
# ---------------------------------------------------------
admin_bp = Blueprint('admin', __name__, url_prefix='/admin')
user_bp = Blueprint('user', __name__)

@admin_bp.url_defaults
def add_admin_id(endpoint, values):
    """Automatically injects the admin_id (aid) into all admin blueprint URLs if a session exists."""
    if 'admin_id' in session and 'aid' not in values:
        values['aid'] = session['admin_id']

@admin_bp.before_request
def admin_session_guard():
    # List of endpoints that don't require session or conflict checks
    public_endpoints = [
        'admin.admin_login', 
        'admin.admin_signup', 
        'admin.verify_otp_get', 
        'admin.verify_otp_post',
        'admin.admin_forgot_password',
        'admin.verify_forgot_otp',
        'admin.admin_reset_password'
    ]
    
    if request.endpoint in public_endpoints:
        return

    # 1. MULTI-SESSION INITIALIZATION
    # Ensure the storage dict exists
    if 'admin_profiles' not in session or not isinstance(session['admin_profiles'], dict):
        session['admin_profiles'] = {}
        # Migration: if old single-session exists, move it to profiles
        if 'admin_id' in session:
            aid = str(session['admin_id'])
            session['admin_profiles'][aid] = {
                'admin_id': session['admin_id'],
                'admin_name': session.get('admin_name'),
                'is_super': session.get('is_super'),
                'profile_image': session.get('profile_image'),
                'session_token': session.get('session_token')
            }

    # 2. CONTEXT SELECTION: Pick which admin profile to use for this request
    url_aid = request.args.get('aid')
    session_aid = session.get('admin_id')
    active_profile = None
    
    if url_aid and str(url_aid) in session['admin_profiles']:
        active_profile = session['admin_profiles'][str(url_aid)]
    elif session_aid and str(session_aid) in session['admin_profiles']:
        # If no aid in URL, but a session exists, use that and then force redirect to include aid
        active_profile = session['admin_profiles'][str(session_aid)]
        # Preserve existing query parameters (like search/filter) during redirect
        query_params = request.args.to_dict()
        query_params.update(request.view_args)
        query_params['aid'] = active_profile['admin_id']
        return redirect(url_for(request.endpoint, **query_params))
    elif session['admin_profiles']:
        # Default to the first available if no specific intent
        first_id = list(session['admin_profiles'].keys())[0]
        # Preserve existing query parameters during redirect
        query_params = request.args.to_dict()
        query_params.update(request.view_args)
        query_params['aid'] = first_id
        return redirect(url_for(request.endpoint, **query_params))
    
    if not active_profile:
        return redirect(url_for('admin.admin_login'))

    # 3. SYNC: Update top-level session keys so templates/routes don't need changes
    # This magic allows the current tab to see it's OWN admin data even if other tabs are different
    session['admin_id'] = active_profile['admin_id']
    session['admin_name'] = active_profile['admin_name']
    session['is_super'] = active_profile['is_super']
    session['profile_image'] = active_profile['profile_image']
    session['session_token'] = active_profile['session_token']

    # 4. SESSION VALIDITY: Ensure the session token is still valid in the database
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT session_token FROM admin WHERE admin_id = ?", (session['admin_id'],))
        admin_data = cursor.fetchone()
        cursor.close()
        conn.close()
        
        if not admin_data or admin_data['session_token'] != session.get('session_token'):
            # Remove this invalid profile from store
            aid_to_remove = str(session['admin_id'])
            if 'admin_profiles' in session and aid_to_remove in session['admin_profiles']:
                del session['admin_profiles'][aid_to_remove]
                session.modified = True
            
            flash("Session expired or logged in from another device.", "warning")
            return redirect(url_for('admin.admin_login'))
    except Exception as e:
        print(f"Session guard error: {e}")

# =================================================================
# SECTION: ADMIN ROUTES (from admin.py)
# =================================================================

# 1. Admin Signup Route: Handles new admin registration requests and sends OTP
@admin_bp.route('/signup', methods=['GET', 'POST'])
def admin_signup():
    if request.method == "GET":
        return render_template("admin/admin_signup.html")

    name = request.form['name']
    email = request.form['email']

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT admin_id FROM admin WHERE email=?", (email,))
    existing_admin = cursor.fetchone()
    cursor.close()
    conn.close()

    if existing_admin:
        flash("This email is already registered. Please login instead.", "danger")
        return redirect(url_for('admin.admin_signup'))

    session['signup_name'] = name
    session['signup_email'] = email

    otp = random.randint(100000, 999999)
    session['otp'] = otp

    try:
        message = Message(
            subject="SmartCart Admin OTP",
            sender=app.config['MAIL_DEFAULT_SENDER'],
            recipients=[email]
        )
        message.body = f"Your OTP for SmartCart Admin Registration is: {otp}"
        mail.send(message)
        flash("OTP sent to your email!", "success")
        return redirect(url_for('admin.verify_otp_get'))
    except Exception as e:
        # Emergency fallback: Print to console so developer can find it in server logs
        print(f"\n[EMERGENCY LOG] Admin Registration OTP for {email} is: {otp}\n")
        print(f"DEBUG: Admin Mail Error: {e}")
        flash(f"Email failed, but your registration is ready! (Dev Note: Check PythonAnywhere Server Log for the OTP: {otp})", "info")
        return redirect(url_for('admin.verify_otp_get'))

# 2. OTP Page Route: Displays the verification form for the registration OTP
@admin_bp.route('/verify-otp', methods=['GET'])
def verify_otp_get():
    return render_template("admin/verify_otp.html")

# 3. OTP Verification Route: Validates the OTP and saves the new admin as 'pending'
@admin_bp.route('/verify-otp', methods=['POST'])
def verify_otp_post():
    user_otp = request.form['otp']
    password = request.form['password']
    profile_image = request.files.get('image')

    if str(session.get('otp')) != str(user_otp):
        flash("Invalid OTP. Try again!", "danger")
        return redirect(url_for('admin.verify_otp_get'))

    hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

    image_filename = None
    if profile_image and profile_image.filename != "":
        filename = secure_filename(profile_image.filename)
        profile_image.save(os.path.join(current_app.config['ADMIN_UPLOAD_FOLDER'], filename))
        image_filename = filename

    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Check if this is the first admin ever registered
        cursor.execute("SELECT COUNT(*) as count FROM admin")
        admin_count = cursor.fetchone()['count']
        
        status = 'pending'
        is_super = 0
        if admin_count == 0:
            status = 'active'
            is_super = 1
            
        cursor.execute("INSERT INTO admin (name, email, password, profile_image, status, is_super) VALUES (?, ?, ?, ?, ?, ?)",
            (session['signup_name'], session['signup_email'], hashed_password, image_filename, status, is_super)
        )
        conn.commit()
        cursor.close()
        conn.close()

        session.pop('otp', None)
        session.pop('signup_name', None)
        session.pop('signup_email', None)

        if is_super:
            flash("Registration successful! As the first administrator, you have been granted Super Admin access and activated automatically.", "success")
        else:
            flash("Registration successful! Your account is pending Super Admin approval.", "info")
            
        return redirect(url_for('admin.admin_login'))

    except Exception as e:
        flash(f"Error during registration: {e}", "danger")
        return redirect(url_for('admin.admin_signup'))

# 4. Admin Login Route: Authenticates admin credentials and manages sessions
@admin_bp.route('/login', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')

        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM admin WHERE email = ?", (email,))
        admin = cursor.fetchone()
        cursor.close()
        conn.close()

        if admin:
            db_password = admin['password']
            if isinstance(db_password, str): 
                db_password_encoded = db_password.encode('utf-8')
            else:
                db_password_encoded = db_password

            if (bcrypt.checkpw(password.encode('utf-8'), db_password_encoded) or password == db_password):
                if admin['status'] != 'active' and not admin['is_super']:
                    flash("Your account is pending approval by the Super Admin.", "warning")
                    return render_template('admin/admin_login.html')
                    
                # Record login event, IP, and unique session token
                browser = request.headers.get('User-Agent', 'Unknown')
                ip_addr = request.remote_addr
                session_token = str(uuid.uuid4())
                now = datetime.now()
                
                try:
                    conn_log = get_db_connection()
                    cursor_log = conn_log.cursor()
                    cursor_log.execute("UPDATE admin SET last_login = ?, session_token = ? WHERE admin_id = ?", 
                                       (now, session_token, admin['admin_id']))
                    cursor_log.execute("INSERT INTO login_logs (admin_id, admin_name, login_time, browser, ip_address) VALUES (?, ?, ?, ?, ?)", 
                                       (admin['admin_id'], admin['name'], now, browser, ip_addr))
                    conn_log.commit()
                    cursor_log.close()
                    conn_log.close()
                except Exception as e:
                    print(f"Error logging login: {e}")

                # Store in the multi-session profile collection
                if 'admin_profiles' not in session or not isinstance(session['admin_profiles'], dict):
                    session['admin_profiles'] = {}
                
                session['admin_profiles'][str(admin['admin_id'])] = {
                    'admin_id': admin['admin_id'],
                    'admin_name': admin['name'],
                    'profile_image': admin['profile_image'],
                    'is_super': admin['is_super'],
                    'session_token': session_token
                }
                
                # Set the current active session (for initial dashboard load)
                session['admin_id'] = admin['admin_id']
                session['admin_name'] = admin['name']
                session['profile_image'] = admin['profile_image']
                session['is_super'] = admin['is_super']
                session['session_token'] = session_token
                
                session.modified = True
                return redirect(url_for('admin.admin_dashboard', aid=admin['admin_id']))
            else:
                return render_template('admin/admin_login.html', error="Invalid Password")
        else:
            flash("Email not found. Please register first!", "danger")
            return redirect(url_for('admin.admin_signup'))

    return render_template('admin/admin_login.html')

# 5. Admin Dashboard Route: Shows account statistics, revenue, and recent orders
@admin_bp.route('/dashboard')
def admin_dashboard():
    if 'admin_id' not in session:
        flash("Please login to access dashboard!", "danger")
        return redirect(url_for('admin.admin_login'))

    admin_login_id = session['admin_id']
    is_super = session.get('is_super', 0)
    
    conn = get_db_connection()
    cursor = conn.cursor()

    if is_super:
        # Only count products from ACTIVE, NON-SUPER administrators
        cursor.execute("""
            SELECT COUNT(p.product_id) as total_products 
            FROM products p 
            JOIN admin a ON p.admin_id = a.admin_id 
            WHERE p.is_active = 1 AND a.status = 'active' AND a.is_super = 0
        """)
        total_products = cursor.fetchone()['total_products']
        
        # Calculate global revenue only from ACTIVE, NON-SUPER administrators
        cursor.execute("""
            SELECT SUM(oi.price * oi.quantity) as total_revenue 
            FROM order_items oi 
            JOIN products p ON oi.product_id = p.product_id 
            JOIN admin a ON p.admin_id = a.admin_id 
            JOIN orders o ON oi.order_id = o.order_id 
            WHERE o.payment_status IN ('paid', 'Paid', 'Completed (Mock)') 
            AND a.status = 'active' AND a.is_super = 0
        """)
        res = cursor.fetchone()
        total_revenue = res['total_revenue'] if res['total_revenue'] else 0
        
        cursor.execute("SELECT COUNT(*) as total_customers FROM users")
        total_customers = cursor.fetchone()['total_customers']
        
        # Order by order_id DESC to show most recent first
        cursor.execute("SELECT o.*, u.name as customer_name FROM orders o JOIN users u ON o.user_id = u.user_id ORDER BY o.order_id DESC LIMIT 5")
        recent_orders = cursor.fetchall()
        # 3. All Administrators Overview with Searching & Filtering
        search_admin = request.args.get('search_admin', '')
        status_filter = request.args.get('status_filter', '')
        
        query_admins = """
            SELECT a.admin_id, a.name, a.email, a.status, a.deletion_requested, a.last_login, 
            (SELECT COUNT(*) FROM products p WHERE p.admin_id = a.admin_id AND p.is_active = 1) as prod_count, 
            (SELECT SUM(oi.price * oi.quantity) FROM order_items oi 
             JOIN products p2 ON oi.product_id = p2.product_id 
             JOIN orders o2 ON oi.order_id = o2.order_id
             WHERE p2.admin_id = a.admin_id AND o2.payment_status IN ('paid', 'Paid', 'Completed (Mock)')) as revenue 
            FROM admin a WHERE a.is_super = 0
        """
        params_admins = []
        if search_admin:
            query_admins += " AND (a.name LIKE ? OR a.email LIKE ?)"
            params_admins.extend([f"%{search_admin}%", f"%{search_admin}%"])
        if status_filter:
            query_admins += " AND a.status = ?"
            params_admins.append(status_filter)
            
        cursor.execute(query_admins, params_admins)
        all_admins = cursor.fetchall()

        cursor.execute("SELECT * FROM admin WHERE status = 'pending'")
        pending_admins = cursor.fetchall()
    else:
        all_admins = []
        cursor.execute("SELECT COUNT(*) as total_products FROM products WHERE admin_id = ? AND is_active = 1", (admin_login_id,))
        total_products = cursor.fetchone()['total_products']
        cursor.execute("SELECT SUM(oi.price * oi.quantity) as total_revenue FROM order_items oi JOIN products p ON oi.product_id = p.product_id JOIN orders o ON oi.order_id = o.order_id WHERE p.admin_id = ? AND o.payment_status IN ('paid', 'Paid', 'Completed (Mock)')", (admin_login_id,))
        res = cursor.fetchone()
        total_revenue = res['total_revenue'] if res['total_revenue'] else 0
        cursor.execute("SELECT COUNT(DISTINCT o.user_id) as total_customers FROM orders o JOIN order_items oi ON o.order_id = oi.order_id JOIN products p ON oi.product_id = p.product_id WHERE p.admin_id = ?", (admin_login_id,))
        total_customers = cursor.fetchone()['total_customers']
        cursor.execute("SELECT DISTINCT o.*, u.name as customer_name FROM orders o JOIN users u ON o.user_id = u.user_id JOIN order_items oi ON o.order_id = oi.order_id JOIN products p ON oi.product_id = p.product_id WHERE p.admin_id = ? ORDER BY o.created_at DESC LIMIT 5", (admin_login_id,))
        recent_orders = cursor.fetchall()
        pending_admins = []

    # Fetch recent login history
    if is_super:
        # Super Admin sees everyone's login history
        cursor.execute("SELECT * FROM login_logs ORDER BY login_time DESC LIMIT 10")
    else:
        # Regular Admin sees only their OWN login history
        cursor.execute("SELECT * FROM login_logs WHERE admin_id = ? ORDER BY login_time DESC LIMIT 10", (admin_login_id,))
    
    recent_logins = cursor.fetchall()

    # Fetch fresh admin details to ensure no session mixing displays old data
    cursor.execute("SELECT name, profile_image FROM admin WHERE admin_id = ?", (admin_login_id,))
    current_admin_db = cursor.fetchone()
    db_admin_name = current_admin_db['name'] if current_admin_db else "Admin"

    cursor.close()
    conn.close()

    return render_template("admin/dashboard.html", 
                           admin_name=db_admin_name,
                           is_super=is_super,
                           total_products=total_products,
                           total_revenue=total_revenue,
                           total_customers=total_customers,
                           recent_orders=recent_orders,
                           pending_admins=pending_admins,
                           all_admins=all_admins,
                           recent_logins=recent_logins)

# 6. Global Orders Route: Displays all platform orders (Super Admin) or specific product orders (Admin)
@admin_bp.route('/all-orders')
def all_orders():
    if 'admin_id' not in session:
        flash("Please login to access this page!", "danger")
        return redirect(url_for('admin.admin_login'))
    is_super = session.get('is_super', 0)
    admin_login_id = session['admin_id']
    conn = get_db_connection()
    cursor = conn.cursor()
    search_order = request.args.get('search_order', '')
    status_filter = request.args.get('status_filter', '')
    
    if is_super:
        query = "SELECT o.*, u.name as customer_name FROM orders o JOIN users u ON o.user_id = u.user_id WHERE 1=1"
        params = []
    else:
        query = "SELECT DISTINCT o.*, u.name as customer_name FROM orders o JOIN users u ON o.user_id = u.user_id JOIN order_items oi ON o.order_id = oi.order_id JOIN products p ON oi.product_id = p.product_id WHERE p.admin_id = ?"
        params = [admin_login_id]

    if search_order:
        query += " AND (u.name LIKE ? OR CAST(o.order_id AS TEXT) LIKE ?)"
        params.extend([f"%{search_order}%", f"%{search_order}%"])
    
    if status_filter:
        query += " AND o.payment_status = ?"
        params.append(status_filter)

    query += " ORDER BY o.order_id DESC"
    cursor.execute(query, params)
    orders = cursor.fetchall()
    cursor.close()
    conn.close()
    return render_template("admin/all_orders.html", orders=orders, is_super=is_super)

# 7. Approve Admin Route: Super Admin functionality to activate newly registered admin accounts
@admin_bp.route('/approve-admin/<int:t_admin_id>')
def approve_admin(t_admin_id):
    if not session.get('is_super'):
        flash("Only Super Admin can perform this action.", "danger")
        return redirect(url_for('admin.admin_dashboard'))
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("UPDATE admin SET status = 'active' WHERE admin_id = ?", (t_admin_id,))
    conn.commit()
    cursor.close()
    conn.close()
    flash("Admin account approved!", "success")
    return redirect(url_for('admin.admin_dashboard'))

# 8. Confirm Delete Admin Route: Super Admin functionality to permanently wipe an admin account
@admin_bp.route('/confirm-delete-admin/<int:t_admin_id>')
def confirm_delete_admin(t_admin_id):
    if not session.get('is_super'):
        flash("Only Super Admin can perform this action.", "danger")
        return redirect(url_for('admin.admin_dashboard'))
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM admin WHERE admin_id = ? AND deletion_requested = 1", (t_admin_id,))
    if not cursor.fetchone():
        conn.close()
        flash("No deletion request found for this admin.", "warning")
        return redirect(url_for('admin.admin_dashboard'))
    cursor.execute("DELETE FROM products WHERE admin_id = ?", (t_admin_id,))
    cursor.execute("DELETE FROM admin WHERE admin_id = ?", (t_admin_id,))
    conn.commit()
    cursor.close()
    conn.close()
    flash("Admin account and all data permanently deleted.", "success")
    return redirect(url_for('admin.admin_dashboard'))

# 9. Reject Delete Request Route: Super Admin functionality to cancel an admin's account deletion request
@admin_bp.route('/reject-delete-request/<int:t_admin_id>')
def reject_delete_request(t_admin_id):
    if not session.get('is_super'):
        flash("Only Super Admin can perform this action.", "danger")
        return redirect(url_for('admin.admin_dashboard'))
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("UPDATE admin SET deletion_requested = 0 WHERE admin_id = ?", (t_admin_id,))
    conn.commit()
    cursor.close()
    conn.close()
    flash("Admin deletion request rejected. Account preserved.", "info")
    return redirect(url_for('admin.admin_dashboard'))

# 10. Admin Inventory View: Super Admin ability to browse any admin's catalog
@admin_bp.route('/view-admin-inventory/<int:t_admin_id>')
def view_admin_inventory(t_admin_id):
    if not session.get('is_super'):
        flash("Unauthorized access.", "danger")
        return redirect(url_for('admin.admin_dashboard'))
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM admin WHERE admin_id = ?", (t_admin_id,))
    target_admin = cursor.fetchone()
    
    # Add filtering for this specific admin's inventory
    cursor.execute("SELECT DISTINCT category FROM products WHERE admin_id = ?", (t_admin_id,))
    categories = cursor.fetchall()

    query = "SELECT * FROM products WHERE admin_id = ? AND is_active = 1"
    params = [t_admin_id]
    search, category_filter = request.args.get('search', ''), request.args.get('category', '')
    if search: 
        query += " AND name LIKE ?"
        params.append("%" + search + "%")
    if category_filter: 
        query += " AND category = ?"
        params.append(category_filter)
        
    cursor.execute(query, params)
    products = cursor.fetchall()
    cursor.close()
    conn.close()
    return render_template("admin/item_list.html", products=products, categories=categories, view_only=True, target_admin_name=target_admin['name'])

# 11. Admin Logout Route: Safely clears admin session data and redirects to login
@admin_bp.route('/logout')
def admin_logout():
    aid = request.args.get('aid')
    if aid and 'admin_profiles' in session and str(aid) in session['admin_profiles']:
        del session['admin_profiles'][str(aid)]
        # If we just logged out the "active" one, pick another or clear
        if str(session.get('admin_id')) == str(aid):
            session.pop('admin_id', None)
            session.pop('admin_name', None)
            session.pop('is_super', None)
            session.pop('profile_image', None)
            session.pop('session_token', None)
        session.modified = True
    else:
        # Global logout
        session.clear()
    
    flash("Logged out successfully.", "success")
    return redirect(url_for('admin.admin_login'))

# 12. Request Deletion Route: Allows regular admins to flag their account for removal
@admin_bp.route('/delete-account')
def delete_admin_account():
    if 'admin_id' not in session: return redirect(url_for('admin.admin_login'))
    admin_id = session['admin_id']
    if session.get('is_super'):
        flash("Super Admin account cannot be deleted.", "danger")
        return redirect(url_for('admin.admin_dashboard'))
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("UPDATE admin SET deletion_requested = 1 WHERE admin_id = ?", (admin_id,))
    conn.commit()
    cursor.close()
    conn.close()
    flash("Your deletion request has been sent to the Super Admin for approval.", "warning")
    return redirect(url_for('admin.admin_dashboard'))

# 13. Add Product Form Route: Displays the page to submit a new product
@admin_bp.route('/add-item', methods=['GET'])
def add_item_page():
    if 'admin_id' not in session: return redirect(url_for('admin.admin_login'))
    return render_template("admin/add_item.html")

# 14. Save Product Route: Processes the product submission and saves the image
@admin_bp.route('/add-item', methods=['POST'])
def add_item():
    if 'admin_id' not in session: return redirect(url_for('admin.admin_login'))
    name, description, category, price = request.form['name'], request.form['description'], request.form['category'], request.form['price']
    stock = request.form.get('stock', 10)
    image_file = request.files['image']
    if image_file.filename == "":
        flash("Please upload a product image!", "danger")
        return redirect(url_for('admin.add_item_page'))
    filename = secure_filename(image_file.filename)
    image_file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        cursor.execute("INSERT INTO products (name, description, category, price, stock, image, admin_id) VALUES (?, ?, ?, ?, ?, ?, ?)", (name, description, category, price, stock, filename, session['admin_id']))
        conn.commit()
        flash("Product added successfully!", "success")
    except Exception as e:
        conn.rollback()
        flash(f"Error adding product: {e}", "danger")
    finally:
        cursor.close()
        conn.close()
    return redirect(url_for('admin.add_item_page'))

# 15. Inventory List Route: Displays the logged-in admin's current products
@admin_bp.route('/item-list')
def item_list():
    if 'admin_id' not in session: return redirect(url_for('admin.admin_login'))
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT DISTINCT category FROM products")
    categories = cursor.fetchall()
    query, params = "SELECT * FROM products WHERE admin_id = ? AND is_active = 1", [session['admin_id']]
    search, category_filter = request.args.get('search', ''), request.args.get('category', '')
    if search: query += " AND name LIKE ?"; params.append("%" + search + "%")
    if category_filter: query += " AND category = ?"; params.append(category_filter)
    cursor.execute(query, params)
    products = cursor.fetchall()
    cursor.close()
    conn.close()
    return render_template("admin/item_list.html", products=products, categories=categories)

# 16. Product Detail View: Shows specific item info for management purposes
@admin_bp.route('/view-item/<int:item_id>')
def view_item(item_id):
    if 'admin_id' not in session: return redirect(url_for('admin.admin_login'))
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM products WHERE product_id = ? AND admin_id = ?", (item_id, session['admin_id']))
    product = cursor.fetchone()
    cursor.close()
    conn.close()
    if not product: flash("Unauthorized access or product not found!", "danger"); return redirect(url_for('admin.item_list'))
    return render_template("admin/view_item.html", product=product)

# 17. Load Update Form Route: Retrieves product data for the editing interface
@admin_bp.route('/update-item/<int:item_id>', methods=['GET'])
def update_item_page(item_id):
    if 'admin_id' not in session: return redirect(url_for('admin.admin_login'))
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM products WHERE product_id = ? AND admin_id = ?", (item_id, session['admin_id']))
    product = cursor.fetchone()
    cursor.close()
    conn.close()
    if not product: flash("Unauthorized access!", "danger"); return redirect(url_for('admin.item_list'))
    return render_template("admin/update_item.html", product=product)

# 18. Process Update Route: Applies changes to product data and handles image replacement
@admin_bp.route('/update-item/<int:item_id>', methods=['POST'])
def update_item(item_id):
    if 'admin_id' not in session: return redirect(url_for('admin.admin_login'))
    name, description, category, price = request.form['name'], request.form['description'], request.form['category'], request.form['price']
    stock, new_image = request.form.get('stock', 10), request.files['image']
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        cursor.execute("SELECT image FROM products WHERE product_id = ? AND admin_id = ? AND is_active = 1", (item_id, session['admin_id']))
        product = cursor.fetchone()
        if not product:
            return redirect(url_for('admin.item_list'))
        final_image = product['image']
        if new_image and new_image.filename != "":
            final_image = secure_filename(new_image.filename)
            new_image.save(os.path.join(app.config['UPLOAD_FOLDER'], final_image))
        cursor.execute("UPDATE products SET name=?, description=?, category=?, price=?, stock=?, image=? WHERE product_id=? AND admin_id=?", (name, description, category, price, stock, final_image, item_id, session['admin_id']))
        conn.commit()
        flash("Product updated!", "success")
    except Exception as e:
        conn.rollback()
        flash(f"Error updating product: {e}", "danger")
    finally:
        cursor.close()
        conn.close()
    return redirect(url_for('admin.item_list'))

@admin_bp.route('/delete-item/<int:item_id>')
def delete_item(item_id):
    if 'admin_id' not in session: return redirect(url_for('admin.admin_login'))
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        # Instead of deleting, we update is_active to 0 (Soft Delete)
        cursor.execute("UPDATE products SET is_active = 0 WHERE product_id=? AND admin_id=?", (item_id, session['admin_id']))
        conn.commit()
        flash("Product marked as inactive/deleted successfully!", "success")
    except Exception as e:
        conn.rollback()
        flash(f"Error deleting product: {e}", "danger")
    finally:
        cursor.close()
        conn.close()
    return redirect(url_for('admin.item_list'))

# 20. Admin Profile Management: Entry point to view or update personal admin information
@admin_bp.route('/profile', methods=['GET', 'POST'])
def admin_profile_view():
    if 'admin_id' not in session: return redirect(url_for('admin.admin_login'))
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        if request.method == 'POST':
            name, email, new_password, new_image = request.form['name'], request.form['email'], request.form['password'], request.files['profile_image']
            cursor.execute("SELECT * FROM admin WHERE admin_id = ?", (session['admin_id'],))
            admin = cursor.fetchone()
            hashed_password = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8') if new_password else admin['password']
            final_image = admin['profile_image']
            if new_image and new_image.filename != "":
                final_image = secure_filename(new_image.filename)
                new_image.save(os.path.join(app.config['ADMIN_UPLOAD_FOLDER'], final_image))
            cursor.execute("UPDATE admin SET name=?, email=?, password=?, profile_image=? WHERE admin_id=?", (name, email, hashed_password, final_image, session['admin_id']))
            conn.commit()
            session['admin_name'], session['profile_image'] = name, final_image
            flash("Profile updated!", "success")
        
        cursor.execute("SELECT * FROM admin WHERE admin_id = ?", (session['admin_id'],))
        admin = cursor.fetchone()
        return render_template("admin/admin_profile.html", admin=admin)
    except Exception as e:
        conn.rollback()
        flash(f"Error updating profile: {e}", "danger")
        return redirect(url_for('admin.admin_dashboard'))
    finally:
        cursor.close()
        conn.close()

# 21. Admin Forgot Password Route: Sends a password reset OTP to the specified email
@admin_bp.route('/forgot-password', methods=['GET', 'POST'])
def admin_forgot_password():
    if request.method == 'POST':
        email = request.form['email']
        conn = get_db_connection(); cursor = conn.cursor()
        cursor.execute("SELECT * FROM admin WHERE email = ?", (email,))
        admin = cursor.fetchone(); cursor.close(); conn.close()
        if admin:
            otp = random.randint(100000, 999999); session['admin_reset_otp'], session['admin_reset_email'] = otp, email
            try:
                message = Message(subject="SmartCart Admin Password Reset OTP", sender=config.MAIL_USERNAME, recipients=[email])
                message.body = f"Your OTP: {otp}"; mail.send(message)
                flash("OTP sent to your email!", "success"); return redirect(url_for('admin.verify_forgot_otp'))
            except Exception as e:
                print(f"Admin Forgot Password Mail Error: {e}")
                flash("Failed to send OTP. Please try again later.", "danger")
        else:
            flash("If that email exists in our system, you will receive an OTP.", "info")
            return redirect(url_for('admin.admin_login'))
    return render_template('admin/forgot_password.html')

# 22. Reset OTP Verification Route: Validates the password recovery OTP for admins
@admin_bp.route('/verify-forgot-otp', methods=['GET', 'POST'])
def verify_forgot_otp():
    if 'admin_reset_email' not in session: return redirect(url_for('admin.admin_forgot_password'))
    if request.method == 'POST' and str(request.form['otp']) == str(session.get('admin_reset_otp')):
        session['admin_otp_verified'] = True; flash("Verified!", "success"); return redirect(url_for('admin.admin_reset_password'))
    return render_template('admin/verify_forgot_otp.html')

# 23. Password Reset Route: Allows admins to set a final new password post-OTP validation
@admin_bp.route('/reset-password', methods=['GET', 'POST'])
def admin_reset_password():
    if not session.get('admin_otp_verified'): return redirect(url_for('admin.admin_forgot_password'))
    if request.method == 'POST':
        new_p, conf_p = request.form['new_password'], request.form['confirm_password']
        if new_p == conf_p:
            hashed = bcrypt.hashpw(new_p.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
            conn = get_db_connection(); cursor = conn.cursor()
            cursor.execute("UPDATE admin SET password = ? WHERE email = ?", (hashed, session['admin_reset_email']))
            conn.commit(); cursor.close(); conn.close()
            session.pop('admin_reset_email', None); session.pop('admin_reset_otp', None); session.pop('admin_otp_verified', None)
            flash("Updated!", "success"); return redirect(url_for('admin.admin_login'))
    return render_template('admin/reset_password.html')

# =================================================================
# SECTION: USER ROUTES (from user.py)
# =================================================================

# 24. User Registration Route: Handles initial registration input and sends OTP
@user_bp.route('/user/register', methods=['GET', 'POST'])
def user_register():
    if request.method == 'GET': return render_template("user/user_register.html")
    
    name = request.form['name']
    email = request.form['email']
    password = request.form['password']
    
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE email=?", (email,))
    if cursor.fetchone(): 
        cursor.close(); conn.close()
        flash("Email already registered! Please login.", "danger")
        return redirect(url_for('user.user_login'))
    
    cursor.close(); conn.close()
    
    # Generate OTP
    otp = random.randint(100000, 999999)
    
    # Store registration info in session
    session['user_signup_name'] = name
    session['user_signup_email'] = email
    # Hash password before storing in session for better security
    session['user_signup_password'] = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
    session['user_signup_otp'] = str(otp)
    
    # Send OTP mail
    try:
        msg = Message(
            subject="Verification Code - SmartCart",
            sender=app.config['MAIL_DEFAULT_SENDER'],
            recipients=[email]
        )
        msg.body = f"Hello {name},\n\nYour SmartCart registration OTP is: {otp}\n\nPlease enter this code to complete your registration.\n\nThank you!"
        mail.send(msg)
        flash("Verification code sent to your email!", "info")
        return redirect(url_for('user.user_verify_register_otp'))
    except Exception as e:
        # Emergency fallback for user registration
        print(f"\n[EMERGENCY LOG] User Registration OTP for {email} is: {otp}\n")
        print(f"DEBUG: User Register Mail error: {e}")
        flash(f"Verification code could not be sent. (Dev Note: Find your OTP {otp} in PythonAnywhere Server Logs)", "info")
        return redirect(url_for('user.user_verify_register_otp'))

# 24b. User Verify OTP Route: Validates the registration code and creates the user account
@user_bp.route('/user/verify-registration', methods=['GET', 'POST'])
def user_verify_register_otp():
    if 'user_signup_email' not in session:
        return redirect(url_for('user.user_register'))
        
    if request.method == 'GET':
        return render_template("user/verify_registration_otp.html")
        
    user_otp = request.form.get('otp')
    if str(user_otp) == str(session.get('user_signup_otp')):
        try:
            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute("INSERT INTO users (name, email, password) VALUES (?, ?, ?)", 
                           (session['user_signup_name'], session['user_signup_email'], session['user_signup_password']))
            conn.commit()
            cursor.close(); conn.close()
            
            # Clear signup session data
            session.pop('user_signup_name', None)
            session.pop('user_signup_email', None)
            session.pop('user_signup_password', None)
            session.pop('user_signup_otp', None)
            
            flash("Registration successful! You can now login.", "success")
            return redirect(url_for('user.user_login'))
        except Exception as e:
            flash(f"Error during registration: {e}", "danger")
            return redirect(url_for('user.user_register'))
    else:
        flash("Invalid OTP! Please try again.", "danger")
        return render_template("user/verify_registration_otp.html")

# 25. User Login Route: Authenticates customer credentials and establishes user sessions
@user_bp.route('/user/login', methods=['GET', 'POST'])
def user_login():
    if request.method == 'POST':
        email, password = request.form['email'], request.form['password']
        conn = get_db_connection(); cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE email = ?", (email,))
        user = cursor.fetchone(); cursor.close(); conn.close()
        
        if user:
            db_password = user['password']
            if isinstance(db_password, str):
                db_password = db_password.encode('utf-8')
                
            if (bcrypt.checkpw(password.encode('utf-8'), db_password) or password == user['password']):
                session['user_id'], session['user_name'] = user['user_id'], user['name']
                flash("Welcome!", "success"); return redirect(url_for('user.user_dashboard'))
            else:
                flash("Invalid password!", "danger")
        else:
            flash("Email not found. Please register first!", "danger")
            return redirect(url_for('user.user_register'))
    return render_template('user/user_login.html')

# 26. User Recovery Route: Sends a password reset OTP to customers
@user_bp.route('/user/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form['email']
        conn = get_db_connection(); cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE email = ?", (email,))
        user = cursor.fetchone(); cursor.close(); conn.close()
        if user:
            otp = random.randint(100000, 999999); session['reset_otp'], session['reset_email'] = otp, email
            try:
                msg = Message(subject="SmartCart Reset OTP", sender=config.MAIL_USERNAME, recipients=[email])
                msg.body = f"OTP: {otp}"; mail.send(msg); flash("OTP sent!", "success"); return redirect(url_for('user.verify_otp_reset'))
            except Exception as e:
                print(f"User Forgot Password Mail Error: {e}")
                flash("Error sending email. Try again later.", "danger")
        else:
            flash("If your email is registered, you will receive an OTP code.", "info")
            return redirect(url_for('user.user_login'))
    return render_template('user/forgot_password.html')

# 27. User OTP Check Route: Verifies the recovery OTP for customer accounts
@user_bp.route('/user/verify-otp-reset', methods=['GET', 'POST'])
def verify_otp_reset():
    if 'reset_email' not in session: return redirect(url_for('user.forgot_password'))
    if request.method == 'POST' and str(request.form['otp']) == str(session.get('reset_otp')):
        session['otp_verified'] = True; return redirect(url_for('user.reset_password'))
    return render_template('user/verify_otp_reset.html')

# 28. User Password Update Route: Handles final password change for customer recovery
@user_bp.route('/user/reset-password', methods=['GET', 'POST'])
def reset_password():
    if not session.get('otp_verified'): return redirect(url_for('user.forgot_password'))
    if request.method == 'POST':
        new_p, conf_p = request.form['new_password'], request.form['confirm_password']
        if new_p == conf_p:
            hashed = bcrypt.hashpw(new_p.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
            conn = get_db_connection(); cursor = conn.cursor()
            cursor.execute("UPDATE users SET password = ? WHERE email = ?", (hashed, session['reset_email']))
            conn.commit(); cursor.close(); conn.close()
            session.pop('reset_email', None); session.pop('reset_otp', None); session.pop('otp_verified', None)
            return redirect(url_for('user.user_login'))
    return render_template('user/reset_password.html')

# 29. User Home Dashboard: Main catalog page showing sorted products for shopping
@user_bp.route('/user/dashboard')
def user_dashboard():
    if 'user_id' not in session: return redirect(url_for('user.user_login'))
    s, c = request.args.get('search', ''), request.args.get('category', '')
    conn = get_db_connection(); cursor = conn.cursor()
    q, p = "SELECT * FROM products WHERE is_active = 1", []
    if s: q += " AND name LIKE ?"; p.append(f"%{s}%")
    if c: q += " AND category = ?"; p.append(c)
    cursor.execute(q + " ORDER BY product_id DESC", p)
    products = cursor.fetchall()
    cursor.execute("SELECT DISTINCT category FROM products WHERE is_active = 1")
    categories = cursor.fetchall(); cursor.close(); conn.close()
    return render_template('user/user_home.html', user_name=session.get('user_name'), products=products, categories=categories)

# 30. User Logout Route: Ends customer session and returns to login
@user_bp.route('/user/logout')
def user_logout():
    session.pop('user_id', None); session.pop('user_name', None)
    flash("Bye!", "success"); return redirect(url_for('user.user_login'))

# 31. Public Product View Route: Displays all products with search and filter options
@user_bp.route('/user/products')
def user_products():
    s, c = request.args.get('search', ''), request.args.get('category', '')
    conn = get_db_connection(); cursor = conn.cursor()
    q, p = "SELECT * FROM products WHERE is_active = 1", []
    if s: q += " AND name LIKE ?"; p.append(f"%{s}%")
    if c: q += " AND category = ?"; p.append(c)
    cursor.execute(q + " ORDER BY product_id DESC", p)
    products = cursor.fetchall()
    cursor.execute("SELECT DISTINCT category FROM products WHERE is_active = 1")
    categories = cursor.fetchall(); cursor.close(); conn.close()
    return render_template('user/user_products.html', products=products, categories=categories)

# 32. Product Details Page: Visualizes detailed specs and description for a single product
@user_bp.route('/user/product-details/<int:product_id>')
def user_product_details(product_id):
    conn = get_db_connection(); cursor = conn.cursor()
    cursor.execute("SELECT * FROM products WHERE product_id = ? AND is_active = 1", (product_id,))
    product = cursor.fetchone(); cursor.close(); conn.close()
    return render_template('user/product_details.html', product=product)

# 33. Add To Cart Route: Saves a chosen product into the user's active shopping cart session
@user_bp.route('/user/add-to-cart/<int:product_id>')
def add_to_cart(product_id):
    if 'user_id' not in session: return redirect(url_for('user.user_login'))
    conn = get_db_connection(); cursor = conn.cursor()
    cursor.execute("SELECT stock FROM products WHERE product_id = ? AND is_active = 1", (product_id,))
    product = cursor.fetchone(); cursor.close(); conn.close()
    if not product or product['stock'] <= 0: return redirect(url_for('user.user_dashboard'))
    cart = session.get('cart', {}); pid = str(product_id)
    if cart.get(pid, 0) + 1 > product['stock']: return redirect(url_for('user.user_dashboard'))
    cart[pid] = cart.get(pid, 0) + 1; session['cart'] = cart
    return redirect(url_for('user.user_dashboard'))

# 34. Shopping Cart View Route: Lists all selected items and calculates subtotal
@user_bp.route('/user/cart')
def view_cart():
    if 'user_id' not in session: return redirect(url_for('user.user_login'))
    cart = session.get('cart', {})
    if not cart: return render_template('user/cart.html', products=[], total=0)
    conn = get_db_connection(); cursor = conn.cursor()
    placeholders = ', '.join(['?'] * len(cart))
    cursor.execute(f"SELECT * FROM products WHERE product_id IN ({placeholders})", list(cart.keys()))
    products = [dict(row) for row in cursor.fetchall()]; cursor.close(); conn.close(); total = 0
    for p in products: 
        p['quantity'] = cart[str(p['product_id'])]; p['subtotal'] = p['price'] * p['quantity']; total += p['subtotal']
    return render_template('user/cart.html', products=products, total=total)

# 35. Quantity Increase Route: Increments the item count in the user's cart
@user_bp.route('/user/increase_quantity/<int:pid>')
def increase_quantity(pid):
    cart = session.get('cart', {}); pid_str = str(pid)
    conn = get_db_connection(); cursor = conn.cursor()
    cursor.execute("SELECT stock FROM products WHERE product_id = ?", (pid,)); p = cursor.fetchone(); cursor.close(); conn.close()
    if pid_str in cart and (not p or cart[pid_str] + 1 <= p['stock']): cart[pid_str] += 1
    session['cart'] = cart; return redirect(url_for('user.view_cart'))

# 36. Quantity Decrease Route: Reduces the item count in the user's cart (removes if zero)
@user_bp.route('/user/decrease_quantity/<int:pid>')
def decrease_quantity(pid):
    cart = session.get('cart', {}); pid_str = str(pid)
    if pid_str in cart:
        if cart[pid_str] > 1: cart[pid_str] -= 1
        else: cart.pop(pid_str)
    session['cart'] = cart; return redirect(url_for('user.view_cart'))

# 37. Remove Item Route: Deletes a specific product entirely from the cart session
@user_bp.route('/user/remove_from_cart/<int:pid>')
def remove_from_cart(pid):
    cart = session.get('cart', {}); pid_str = str(pid)
    if pid_str in cart: cart.pop(pid_str)
    session['cart'] = cart; return redirect(url_for('user.view_cart'))

# 38. AJAX Cart Add Route: Async method to add products to cart without refreshing the page
@user_bp.route('/user/add_to_cart_ajax/<int:product_id>')
def add_to_cart_ajax(product_id):
    if 'user_id' not in session: return jsonify({"status": "error"}), 401
    conn = get_db_connection(); cursor = conn.cursor()
    cursor.execute("SELECT stock FROM products WHERE product_id = ?", (product_id,)); p = cursor.fetchone(); cursor.close(); conn.close()
    if not p or p['stock'] <= 0: return jsonify({"status": "error"})
    cart = session.get('cart', {}); pid = str(product_id)
    if cart.get(pid, 0) + 1 > p['stock']: return jsonify({"status": "limit"})
    cart[pid] = cart.get(pid, 0) + 1; session['cart'] = cart
    return jsonify({"status": "success", "cart_count": len(cart)})

# 39. Shipping Address Route: Manages the selection or entry of a checkout address
@user_bp.route('/user/address', methods=['GET', 'POST'])
def user_address():
    if 'user_id' not in session: return redirect(url_for('user.user_login'))
    if request.method == 'POST':
        if 'address_id' in request.form:
            conn = get_db_connection(); cursor = conn.cursor()
            cursor.execute("SELECT * FROM user_addresses WHERE address_id = ? AND user_id = ?", (request.form['address_id'], session['user_id']))
            a = cursor.fetchone(); cursor.close(); conn.close()
            if a:
                session['user_address'] = {'full_name': a['full_name'], 'phone': a['phone'], 'address': a['address_line'], 'city': a['city'], 'state': a['state'], 'zipcode': a['pincode']}
                return redirect(url_for('user.user_pay'))
        f, p, al, c, s, pc = request.form.get('full_name'), request.form.get('phone'), request.form.get('address_line'), request.form.get('city'), request.form.get('state'), request.form.get('pincode')
        if all([f, p, al, c, s, pc]):
            conn = get_db_connection(); cursor = conn.cursor()
            cursor.execute("INSERT INTO user_addresses (user_id, full_name, phone, address_line, city, state, pincode) VALUES (?, ?, ?, ?, ?, ?, ?)", (session['user_id'], f, p, al, c, s, pc))
            conn.commit(); cursor.close(); conn.close()
            session['user_address'] = {'full_name': f, 'phone': p, 'address': al, 'city': c, 'state': s, 'zipcode': pc}
            return redirect(url_for('user.user_pay'))
    conn = get_db_connection(); cursor = conn.cursor()
    cursor.execute("SELECT * FROM user_addresses WHERE user_id = ? ORDER BY created_at DESC", (session['user_id'],))
    saved = cursor.fetchall(); cursor.close(); conn.close()
    return render_template('user/address.html', saved_addresses=saved)

# 40. Delete Address Route: Allows users to permanently remove a saved shipping address
@user_bp.route('/user/delete-address/<int:address_id>')
def delete_address(address_id):
    if 'user_id' not in session: return redirect(url_for('user.user_login'))
    conn = get_db_connection(); cursor = conn.cursor()
    cursor.execute("DELETE FROM user_addresses WHERE address_id = ? AND user_id = ?", (address_id, session['user_id']))
    conn.commit(); cursor.close(); conn.close()
    return redirect(url_for('user.user_address'))

# 41. Buy Now Shortcut Route: Bypasses the cart to immediately checkout with one item
@user_bp.route('/user/buy-now/<int:product_id>')
def buy_now(product_id):
    if 'user_id' not in session: return redirect(url_for('user.user_login'))
    session['cart'] = {str(product_id): 1}; return redirect(url_for('user.user_address'))

# 42. Payment Gateway Route: Generates an active Razorpay order ID for the checkout total
@user_bp.route('/user/pay')
def user_pay():
    if 'user_id' not in session: return redirect(url_for('user.user_login'))
    cart = session.get('cart', {})
    if not cart: return redirect(url_for('user.user_dashboard'))
    conn = get_db_connection(); cursor = conn.cursor()
    placeholders = ', '.join(['?'] * len(cart))
    cursor.execute(f"SELECT * FROM products WHERE product_id IN ({placeholders})", list(cart.keys()))
    products = cursor.fetchall(); cursor.close(); conn.close(); total = sum(p['price'] * cart[str(p['product_id'])] for p in products)
    try:
        razor_order = razorpay_client.order.create({"amount": int(total * 100), "currency": "INR", "receipt": f"rcpt_{session['user_id']}_{random.randint(1000, 9999)}", "payment_capture": 1})
        return render_template('user/payment.html', order_id=razor_order['id'], amount=total, key_id=config.RAZORPAY_KEY_ID)
    except Exception as e: 
        print(f"Razorpay order Error: {e}")
        flash(f"Payment gateway error. Please try again later. (Is your .env correctly configured?)", "danger")
        return redirect(url_for('user.view_cart'))

def _create_order_in_db(uid, cart, payment_status, razor_oid, razor_pid=None):
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        now = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        
        placeholders = ', '.join(['?'] * len(cart))
        cursor.execute(f"SELECT * FROM products WHERE product_id IN ({placeholders})", list(cart.keys()))
        products = cursor.fetchall()
        total = sum(p['price'] * cart[str(p['product_id'])] for p in products)
        
        a = session.get('user_address', {})
        addr = f"Full Name: {a.get('full_name')}\nAddress: {a.get('address')}\nCity: {a.get('city')}\nState: {a.get('state')}\nPincode: {a.get('zipcode')}\nPhone: {a.get('phone')}"

        cursor.execute("INSERT INTO orders (user_id, amount, payment_status, razorpay_order_id, razorpay_payment_id, shipping_address, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)", 
                       (uid, total, payment_status, razor_oid, razor_pid, addr, now))
        oid = cursor.lastrowid
        
        for p in products:
            q = cart[str(p['product_id'])]
            cursor.execute("UPDATE products SET stock = stock - ? WHERE product_id = ?", (q, p['product_id']))
            cursor.execute("INSERT INTO order_items (order_id, product_id, product_name, quantity, price) VALUES (?, ?, ?, ?, ?)", 
                           (oid, p['product_id'], p['name'], q, p['price']))
        
        conn.commit()
        session.pop('cart', None)
        return oid
    except Exception as e:
        if conn: conn.rollback()
        raise e
    finally:
        if cursor: cursor.close()
        if conn: conn.close()

# 43. Payment Landing Route: Basic generic route to confirm receipt of payment signal
@user_bp.route('/user/payment-success')
def payment_success(): return render_template('user/payment_success.html')

# 44. Secure Verification Route: Validates the Razorpay signature to prevent fraud and records the order
@user_bp.route('/user/verify-payment', methods=['POST'])
def verify_payment():
    d = request.form; ro, rp, rs = d.get('razorpay_order_id'), d.get('razorpay_payment_id'), d.get('razorpay_signature')
    try:
        razorpay_client.utility.verify_payment_signature({'razorpay_order_id': ro, 'razorpay_payment_id': rp, 'razorpay_signature': rs})
        oid = _create_order_in_db(session['user_id'], session['cart'], 'Paid', ro, rp)
        send_order_email(oid)
        return redirect(url_for('user.order_success', order_db_id=oid))
    except Exception as e: 
        print(f"Razorpay verification Error: {e}")
        flash("Unauthorized or Invalid payment attempted!", "danger")
        return redirect(url_for('user.view_cart'))

# 45. Final Checkout Success: Displays a confirmation of the order and the unique order ID
@user_bp.route('/user/order-success/<int:order_db_id>')
def order_success(order_db_id):
    conn = get_db_connection(); cursor = conn.cursor()
    cursor.execute("SELECT * FROM orders WHERE order_id = ? AND user_id = ?", (order_db_id, session['user_id']))
    order = cursor.fetchone(); cursor.close(); conn.close(); return render_template('user/order_success.html', order=order)

# 46. Order History Route: Lets customers browse through their previous successful purchases
@user_bp.route('/user/my-orders')
def my_orders():
    conn = get_db_connection(); cursor = conn.cursor()
    cursor.execute("SELECT * FROM orders WHERE user_id = ?", (session['user_id'],))
    orders = cursor.fetchall(); cursor.close(); conn.close(); return render_template('user/my_orders.html', orders=orders)

# 47. Invoice PDF Route: Generates and triggers download of a custom-styled PDF receipt
@user_bp.route('/user/download_invoice/<int:order_id>')
def download_invoice(order_id):
    conn = get_db_connection(); cursor = conn.cursor()
    cursor.execute("SELECT o.*, u.name as user_name, u.email as user_email FROM orders o JOIN users u ON o.user_id = u.user_id WHERE o.order_id = ? AND o.user_id = ?", (order_id, session['user_id']))
    order = cursor.fetchone()
    if not order: cursor.close(); conn.close(); return "404"
    cursor.execute("SELECT * FROM order_items WHERE order_id = ?", (order_id,))
    items = cursor.fetchall(); cursor.close(); conn.close()
    html = render_template('user/invoice.html', order=order, items=items); pdf = generate_pdf(html)
    response = make_response(pdf.read()); response.headers['Content-Type'] = 'application/pdf'; response.headers['Content-Disposition'] = f'attachment; filename=invoice_{order_id}.pdf'; return response

# 48. Customer Account Route: Interface to edit personal user profile settings
@user_bp.route('/user/profile', methods=['GET', 'POST'])
def user_profile():
    if 'user_id' not in session: return redirect(url_for('user.user_login'))
    conn = get_db_connection(); cursor = conn.cursor()
    if request.method == 'POST':
        n, e, p = request.form.get('name'), request.form.get('email'), request.form.get('password')
        if p:
            hashed = bcrypt.hashpw(p.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
            cursor.execute("UPDATE users SET name = ?, email = ?, password = ? WHERE user_id = ?", (n, e, hashed, session['user_id']))
        else: cursor.execute("UPDATE users SET name = ?, email = ? WHERE user_id = ?", (n, e, session['user_id']))
        conn.commit()
    cursor.execute("SELECT * FROM users WHERE user_id = ?", (session['user_id'],)); user = cursor.fetchone(); cursor.close(); conn.close()
    return render_template('user/user_profile.html', user=user)

# 49. Static About Route: Static page describing the SmartCart mission
@user_bp.route('/about')
def about(): return render_template('about.html')

# 50. Static Contact Route: Static page for business and support inquiries
@user_bp.route('/contact', methods=['GET', 'POST'])
def contact():
    if request.method == 'POST':
        name = request.form.get('name')
        email = request.form.get('email')
        subject = request.form.get('subject')
        message_text = request.form.get('message')
        
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('''INSERT INTO contact_messages (name, email, subject, message)
                          VALUES (?, ?, ?, ?)''', (name, email, subject, message_text))
        conn.commit()
        cursor.close()
        conn.close()

        try:
            msg = Message(subject=f"New Contact Inquiry: {subject}",
                          sender=config.MAIL_USERNAME,
                          recipients=[config.MAIL_USERNAME]) # owner's email
            msg.body = f"Name: {name}\nEmail: {email}\nSubject: {subject}\n\nMessage:\n{message_text}"
            mail.send(msg)
        except Exception as e:
            print(f"Error sending contact email: {e}")
            
        flash("Thank you for your message! We will get back to you soon.", "success")
        return redirect(url_for('user.contact'))
    return render_template('contact.html')

@user_bp.route('/user/auto-login')
def auto_login():
    """Automatically logs in a user or creates a guest account if none exists."""
    if session.get('user_id'):
        return redirect(url_for('user.user_dashboard'))
        
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Find the latest user or create a guest
    cursor.execute("SELECT * FROM users ORDER BY user_id DESC LIMIT 1")
    user = cursor.fetchone()
    
    if user:
        session['user_id'] = user['user_id']
        session['user_name'] = user['name']
        flash(f"Welcome back, {user['name']}!", "success")
    else:
        guest_pw = bcrypt.hashpw('guest123'.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
        cursor.execute("INSERT INTO users (name, email, password) VALUES (?, ?, ?)", 
                       ('Guest User', 'guest@smartcart.com', guest_pw))
        conn.commit()
        session['user_id'] = cursor.lastrowid
        session['user_name'] = 'Guest User'
        flash("Guest account created and logged in.", "success")
        
    cursor.close()
    conn.close()
    session.modified = True
    return redirect(url_for('user.user_dashboard'))


# =================================================================
# MAIN ENTRY & GLOBAL CONFIG (from app.py originals)
# =================================================================

# Initialize the database on startup (needed for PythonAnywhere/WSGI)
init_db()

app.register_blueprint(admin_bp)
app.register_blueprint(user_bp)

@app.context_processor
def utility_processor():
    categories, cart_count = [], 0
    try:
        conn = get_db_connection(); cursor = conn.cursor()
        cursor.execute("SELECT DISTINCT category FROM products WHERE is_active = 1")
        categories = [row['category'] for row in cursor.fetchall()]; cursor.close(); conn.close()
    except: pass
    if 'cart' in session: cart_count = len(session['cart'])
    return {"global_categories": categories, "global_cart_count": cart_count}

# 51. Entry Redirect: Routes the root URL directly to the login gate
@app.route("/")
def index():
    return redirect(url_for('user.user_login'))

if __name__ == '__main__':
    # Listen on all interfaces (0.0.0.0) so other devices in the network can access/scan
    app.run(host='0.0.0.0', port=5000, debug=True)
