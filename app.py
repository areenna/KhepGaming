from flask import Flask, render_template, request, redirect, url_for, session, g, flash
from werkzeug.security import generate_password_hash, check_password_hash
import mysql.connector
from mysql.connector import errorcode
import re
from decimal import Decimal, ROUND_HALF_UP

app = Flask(__name__)
app.secret_key = "change-this-secret-key"  # required for sessions & flash

# ----------------------------
# MySQL connection settings
# ----------------------------
DB_NAME = "khepgaming"

MYSQL_CONFIG = {
    "host":     "127.0.0.1",   # or your DB host
    "user":     "root",        # your MySQL user
    "password": "areen",
    "port":     3306,
    "database": DB_NAME
}

# ----------------------------
# Database connection helpers
# ----------------------------
def get_db_connection():
    """Connect to existing khepgaming database."""
    conn = mysql.connector.connect(
        host=MYSQL_CONFIG["host"],
        user=MYSQL_CONFIG["user"],
        password=MYSQL_CONFIG["password"],
        port=MYSQL_CONFIG["port"],
        database=MYSQL_CONFIG["database"],
        autocommit=True,
    )
    return conn

@app.before_request
def before_request():
    g.db = get_db_connection()

@app.teardown_request
def teardown_request(exception):
    db = getattr(g, "db", None)
    if db is not None and db.is_connected():
        db.close()
        
        
        
import os
from werkzeug.utils import secure_filename

APP_ROOT = os.path.dirname(os.path.abspath(__file__))
UPLOAD_FOLDER = os.path.join(APP_ROOT, "static", "uploads")
ALLOWED_EXTENSIONS = {"png", "jpg", "jpeg", "gif", "webp"}
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER
app.config["MAX_CONTENT_LENGTH"] = 10 * 1024 * 1024  # 10MB

def allowed_file(filename: str) -> bool:
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS

def save_image(file_storage):
    if not file_storage or file_storage.filename == "":
        return None
    if not allowed_file(file_storage.filename):
        return None
    fname = secure_filename(file_storage.filename)
    base, ext = os.path.splitext(fname)
    import time
    fname = f"{base}_{int(time.time())}{ext.lower()}"
    dest = os.path.join(app.config["UPLOAD_FOLDER"], fname)
    file_storage.save(dest)
    return f"/static/uploads/{fname}"  # store WEB path in DB


# ----------------------------
# Simple User helpers
# ----------------------------
def create_user(name, nid, phone, email, password):
    """Create user; returns (ok, error_message)."""
    hashed = generate_password_hash(password)
    try:
        cur = g.db.cursor(dictionary=True)
        cur.execute(
            "INSERT INTO users (name, nid, phone, email, password_hash) VALUES (%s, %s, %s, %s, %s)",
            (name, nid, phone, email, hashed),
        )
        cur.close()
        return True, None
    except mysql.connector.Error as e:
        if e.errno == errorcode.ER_DUP_ENTRY:
            return False, "Email or phone already registered."
        return False, "Could not create user."

def find_user_by_phone(phone):
    cur = g.db.cursor(dictionary=True)
    cur.execute("SELECT * FROM users WHERE phone=%s", (phone,))
    row = cur.fetchone()
    cur.close()
    return row

def find_user_by_id(user_id):
    cur = g.db.cursor(dictionary=True)
    cur.execute("SELECT * FROM users WHERE id=%s", (user_id,))
    row = cur.fetchone()
    cur.close()
    return row

# -------- Admin helpers --------
def create_admin(name, phone, email, password, secret):
    """Create an admin row. DB enforces secret via CHECK/trigger."""
    hashed = generate_password_hash(password)
    try:
        cur = g.db.cursor(dictionary=True)
        cur.execute(
            "INSERT INTO admins (name, phone, email, password_hash, secret_code) VALUES (%s, %s, %s, %s, %s)",
            (name, phone, email, hashed, secret),
        )
        g.db.commit()
        cur.close()
        return True, None
    except mysql.connector.Error as e:
        # 1062 = duplicate entry; 3819 = CHECK constraint violation (invalid secret)
        if e.errno == 1062:
            return False, "Phone or email is already registered as admin."
        if e.errno == 3819:
            return False, "Invalid secret code."
        return False, "Could not create admin."

def find_admin_by_phone(phone):
    cur = g.db.cursor(dictionary=True)
    cur.execute("SELECT * FROM admins WHERE phone=%s", (phone,))
    row = cur.fetchone()
    cur.close()
    return row

def find_admin_by_id(admin_id):
    cur = g.db.cursor(dictionary=True)
    cur.execute("SELECT * FROM admins WHERE id=%s", (admin_id,))
    row = cur.fetchone()
    cur.close()
    return row


# ----------------------------
# Validators
# ----------------------------
PHONE_RE = re.compile(r"^01\d{9}$")       # must start with 01 and be 11 digits total
NID_RE   = re.compile(r"^\d{10,17}$")     # 10–17 digits

# ----------------------------
# Routes
# ----------------------------
@app.route("/")
def landing():
    return render_template("landing.html", app_name="KhepGaming")

@app.route("/signup", methods=["GET", "POST"])
def signup():
    if request.method == "POST":
        name = request.form.get("name", "").strip()
        nid = request.form.get("nid", "").strip()
        phone = request.form.get("phone", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")

        if not all([name, nid, phone, email, password]):
            flash("Please fill all fields.")
            return redirect(url_for("signup"))
        if len(password) < 6:
            flash("Password must be at least 6 characters.")
            return redirect(url_for("signup"))
        if not PHONE_RE.match(phone):
            flash("Phone must start with 01 and be exactly 11 digits.")
            return redirect(url_for("signup"))
        if not NID_RE.match(nid):
            flash("NID must be 10 to 17 digits.")
            return redirect(url_for("signup"))

        ok, err = create_user(name, nid, phone, email, password)
        if not ok:
            flash(err)
            return redirect(url_for("signup"))

        user = find_user_by_phone(phone)
        session["user_id"] = user["id"]
        return redirect(url_for("profile"))

    return render_template("signup.html", app_name="KhepGaming")

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        phone = (request.form.get("phone") or "").strip()
        password = request.form.get("password") or ""

        if not PHONE_RE.match(phone):
            flash("Enter a valid phone: starts with 01 and 11 digits total.")
            return redirect(url_for("login"))

        user = find_user_by_phone(phone)
        if user and check_password_hash(user["password_hash"], password):
            if user.get("is_suspended"):   # 🚨 check suspension
                session["user_id"] = user["id"]  # still log them in so they can logout
                return redirect(url_for("suspended_page"))
            session["user_id"] = user["id"]
            return redirect(url_for("dashboard"))
        else:
            flash("Invalid phone or password.")
            return redirect(url_for("login"))

    return render_template("login.html", app_name="KhepGaming")


@app.route("/suspended")
def suspended_page():
    # must be logged in
    if not session.get("user_id"):
        flash("Please log in first.")
        return redirect(url_for("login"))

    return render_template("suspended.html")


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("landing"))

@app.route("/profile")
def profile():
    user_id = session.get("user_id")
    if not user_id:
        flash("Please log in first.")
        return redirect(url_for("login"))

    cur = g.db.cursor(dictionary=True)
    cur.execute("SELECT id, name, email, phone, nid, wallet, created_at FROM users WHERE id=%s", (user_id,))
    user = cur.fetchone()
    cur.close()

    if not user:
        session.clear()
        flash("User not found. Please log in again.")
        return redirect(url_for("login"))

    return render_template("profile.html", user=user)

# ========= REPLACE YOUR EXISTING ADMIN SIGNUP ROUTES WITH THIS =========
@app.route("/admin/signup", methods=["GET", "POST"])
def admin_signup_page():
    if request.method == "GET":
        return render_template("adsign.html", app_name="KhepGaming")

    # POST: create admin (DB enforces secret via CHECK/trigger)
    name = (request.form.get("name") or "").strip()
    phone = (request.form.get("phone") or "").strip()
    email = (request.form.get("email") or "").strip().lower()
    password = request.form.get("password") or ""
    secret = (request.form.get("secret") or "").strip()  # not validated here

    if not all([name, phone, email, password, secret]):
        flash("Please fill all fields.")
        return redirect(url_for("admin_signup_page"))
    if not PHONE_RE.match(phone):
        flash("Phone must start with 01 and be exactly 11 digits.")
        return redirect(url_for("admin_signup_page"))
    if len(password) < 6:
        flash("Password must be at least 6 characters.")
        return redirect(url_for("admin_signup_page"))

    ok, err = create_admin(name, phone, email, password, secret)
    if not ok:
        flash(err)
        return redirect(url_for("admin_signup_page"))

    flash("Admin account created. Please log in.")
    return redirect(url_for("admin_login_page"))


# ========= REPLACE YOUR EXISTING ADMIN LOGIN ROUTES WITH THIS =========
@app.route("/admin/login", methods=["GET", "POST"])
def admin_login_page():
    if request.method == "GET":
        return render_template("adlogin.html", app_name="KhepGaming")

    # POST: check phone + password + secret
    phone = (request.form.get("phone") or "").strip()
    password = request.form.get("password") or ""
    secret = (request.form.get("secret") or "").strip()

    if not PHONE_RE.match(phone):
        flash("Enter a valid phone: starts with 01 and 11 digits total.")
        return redirect(url_for("admin_login_page"))
    if secret != "579011":
        flash("Invalid secret code.")
        return redirect(url_for("admin_login_page"))

    admin = find_admin_by_phone(phone)
    if admin and check_password_hash(admin["password_hash"], password):
        session["admin_id"] = admin["id"]
        return redirect(url_for("admin_home"))
    else:
        flash("Invalid phone or password.")
        return redirect(url_for("admin_login_page"))

# --- Admin Logout ---
@app.route("/admin/logout", methods=["GET"])
def admin_logout():
    session.pop("admin_id", None)
    flash("Logged out from admin.")
    return redirect(url_for("landing"))

@app.route("/wallet", methods=["GET"])
def wallet():
    user_id = session.get("user_id")
    if not user_id:
        flash("Please log in first.")
        return redirect(url_for("login"))

    user = find_user_by_id(user_id)
    if not user:
        session.clear()
        flash("User not found. Please log in again.")
        return redirect(url_for("login"))

    user_dict = {
        "id": user["id"],
        "name": user["name"],
        "email": user["email"],
        "phone": user["phone"],
        "nid": user["nid"],
        "wallet": user.get("wallet", 0),
        "created_at": user["created_at"],
    }
    return render_template("wallet.html", user=user_dict, app_name="KhepGaming")



@app.route("/wallet/cashin", methods=["POST"])
def wallet_cashin():
    user_id = session.get("user_id")
    if not user_id:
        flash("Please log in first.")
        return redirect(url_for("login"))

    phone = (request.form.get("phone") or "").strip()
    amount_raw = (request.form.get("amount") or "").strip()

    if not PHONE_RE.match(phone):
        flash("Enter a valid phone: starts with 01 and 11 digits total.")
        return redirect(url_for("cashin_page"))

    try:
        amount = Decimal(amount_raw)
    except Exception:
        flash("Enter a valid amount.")
        return redirect(url_for("cashin_page"))
    if amount <= 0:
        flash("Amount must be greater than 0.")
        return redirect(url_for("cashin_page"))

    # Update wallet and COMMIT
    cur = g.db.cursor()
    cur.execute("UPDATE users SET wallet = wallet + %s WHERE id = %s", (amount, user_id))
    g.db.commit()
    cur.close()

    flash("Cash In successful.")
    return redirect(url_for("wallet"))

@app.route("/wallet/cashout", methods=["POST"])
def wallet_cashout():
    user_id = session.get("user_id")
    if not user_id:
        flash("Please log in first.")
        return redirect(url_for("login"))

    phone = (request.form.get("phone") or "").strip()
    amount_raw = (request.form.get("amount") or "").strip()

    if not PHONE_RE.match(phone):
        flash("Enter a valid phone: starts with 01 and 11 digits total.")
        return redirect(url_for("cashout_page"))

    try:
        amount = Decimal(amount_raw)
    except Exception:
        flash("Enter a valid amount.")
        return redirect(url_for("cashout_page"))
    if amount <= 0:
        flash("Amount must be greater than 0.")
        return redirect(url_for("cashout_page"))
    me = find_user_by_id(user_id)
    current_balance = Decimal(str(me.get("wallet", 0)))
    if current_balance < amount:
        flash("Not enough Cash")
        return redirect(url_for("wallet"))

    # Deduct and COMMIT
    cur = g.db.cursor()
    cur.execute("UPDATE users SET wallet = wallet - %s WHERE id = %s", (amount, user_id))
    g.db.commit()
    cur.close()

    flash("Cash Out successful.")
    return redirect(url_for("wallet"))

@app.route("/wallet/cashin", methods=["GET"])
def cashin_page():
    return render_template("cashin.html", app_name="KhepGaming")

@app.route("/wallet/cashout", methods=["GET"])
def cashout_page():
    return render_template("cashout.html", app_name="KhepGaming")

# --- Edit Profile (GET) ---
@app.route("/profile/edit", methods=["GET"])
def edit_profile_page():
    user_id = session.get("user_id")
    user = find_user_by_id(user_id)
    if not user:
        session.clear()
        flash("User not found. Please log in again.")
        return redirect(url_for("login"))

    user_dict = {
        "id": user["id"],
        "name": user["name"],
        "email": user["email"],
        "phone": user["phone"],
        "nid": user["nid"],
        "wallet": user.get("wallet", 0),
        "created_at": user["created_at"],
    }
    return render_template("edit.html", user=user_dict, app_name="KhepGaming")


# --- Edit Profile (POST) ---
@app.route("/profile/edit", methods=["POST"])
def edit_profile_submit():
    user_id = session.get("user_id")
    if not user_id:
        flash("Please log in first.")
        return redirect(url_for("login"))

    name = (request.form.get("name") or "").strip()
    nid = (request.form.get("nid") or "").strip()
    phone = (request.form.get("phone") or "").strip()
    email = (request.form.get("email") or "").strip().lower()
    new_password = request.form.get("password") or ""

    if not all([name, nid, phone, email]):
        flash("Please fill all required fields.")
        return redirect(url_for("edit_profile_page"))

    if not PHONE_RE.match(phone):
        flash("Phone must start with 01 and be exactly 11 digits.")
        return redirect(url_for("edit_profile_page"))

    if not NID_RE.match(nid):
        flash("NID must be 10 to 17 digits.")
        return redirect(url_for("edit_profile_page"))

    # Fetch current user to keep password if blank
    me = find_user_by_id(user_id)
    if not me:
        session.clear()
        flash("User not found. Please log in again.")
        return redirect(url_for("login"))

    password_hash = me["password_hash"]
    if new_password.strip():
        if len(new_password) < 6:
            flash("Password must be at least 6 characters.")
            return redirect(url_for("edit_profile_page"))
        password_hash = generate_password_hash(new_password)

    try:
        cur = g.db.cursor()
        cur.execute(
            """
            UPDATE users
               SET name=%s, nid=%s, phone=%s, email=%s, password_hash=%s
             WHERE id=%s
            """,
            (name, nid, phone, email, password_hash, user_id),
        )
        g.db.commit()
        cur.close()
    except mysql.connector.Error as e:
        # Handle duplicate phone/email
        if e.errno == errorcode.ER_DUP_ENTRY:
            flash("That phone or email is already in use.")
        else:
            flash("Could not update profile.")
        return redirect(url_for("edit_profile_page"))

    flash("Profile updated successfully.")
    return redirect(url_for("profile"))

from decimal import Decimal, InvalidOperation
from datetime import date

@app.route("/rent/new", methods=["GET", "POST"])
def rent_new():
    # must be logged in
    uid = session.get("user_id")
    if not uid:
        flash("Please log in first.")
        return redirect(url_for("login"))

    if request.method == "POST":
        # Block suspended users from listing
        cur = g.db.cursor(dictionary=True)
        cur.execute("SELECT is_suspended FROM users WHERE id=%s", (uid,))
        u = cur.fetchone()
        if u and u.get("is_suspended"):
            cur.close()
            flash("Your account is suspended. You cannot list products.")
            return redirect(url_for("suspended_page"))

        # Read form fields
        title       = (request.form.get("title") or "").strip()
        category    = (request.form.get("category") or "").strip()
        description = (request.form.get("description") or "").strip()
        location    = (request.form.get("location") or "").strip()
        available_from = (request.form.get("available_from") or "").strip()
        available_to   = (request.form.get("available_to") or "").strip()

        # Validate price
        price_raw = (request.form.get("price_per_day") or "").strip()
        try:
            price_per_day = Decimal(price_raw)
            if price_per_day <= 0:
                raise InvalidOperation
        except Exception:
            cur.close()
            flash("Enter a valid positive price per day.")
            return redirect(url_for("rent_new"))

        # Validate dates
        try:
            af = date.fromisoformat(available_from)  # YYYY-MM-DD
            at = date.fromisoformat(available_to)
            if at < af:
                flash("Available To date cannot be earlier than Available From.")
                cur.close()
                return redirect(url_for("rent_new"))
        except Exception:
            cur.close()
            flash("Enter valid dates (YYYY-MM-DD).")
            return redirect(url_for("rent_new"))

        # Handle image upload (returns '/static/uploads/filename.ext' or None)
        image_file = request.files.get("image")
        image_url = save_image(image_file)  # requires helper defined earlier

        # Insert product
        try:
            cur.execute("""
                INSERT INTO products
                  (owner_id, title, category, description, price_per_day, location, image_url, available_from, available_to, status)
                VALUES
                  (%s,%s,%s,%s,%s,%s,%s,%s,%s,'available')
            """, (uid, title, category, description, str(price_per_day), location,
                  image_url, af, at))
            product_id = cur.lastrowid
            g.db.commit()
            flash("Product listed successfully!")
        except Exception:
            g.db.rollback()
            flash("Could not list the product. Please try again.")
            cur.close()
            return redirect(url_for("rent_new"))
        finally:
            cur.close()

        # Go to the product details page
        return redirect(url_for("product_details", product_id=product_id))

    # GET → show form
    return render_template("rentout.html")


from datetime import date

@app.route("/dashboard")
def dashboard():
    cur = None
    try:
        q            = (request.args.get("q") or "").strip()
        category     = (request.args.get("category") or "").strip()
        location     = (request.args.get("location") or "").strip()
        price_min    = request.args.get("price_min")
        price_max    = request.args.get("price_max")
        date_from    = (request.args.get("from") or "").strip()
        date_to      = (request.args.get("to") or "").strip()
        rating_min   = request.args.get("rating_min")
        status       = (request.args.get("status") or "available").strip()  # default: only available

        where = []
        params = []

        # Text search over title/description/location
        if q:
            where.append("(p.title LIKE %s OR p.description LIKE %s OR p.location LIKE %s)")
            like = f"%{q}%"
            params.extend([like, like, like])

        if category:
            where.append("p.category = %s")
            params.append(category)

        if location:
            where.append("p.location LIKE %s")
            params.append(f"%{location}%")

        # Price range
        if price_min:
            where.append("p.price_per_day >= %s")
            params.append(price_min)
        if price_max:
            where.append("p.price_per_day <= %s")
            params.append(price_max)

        # Availability overlap with requested window:
        # overlap if p.available_from <= to AND p.available_to >= from
        # handle single-ended ranges too
        if date_from and date_to:
            where.append("(p.available_from <= %s AND p.available_to >= %s)")
            params.extend([date_to, date_from])
        elif date_from:
            where.append("(p.available_to >= %s)")
            params.append(date_from)
        elif date_to:
            where.append("(p.available_from <= %s)")
            params.append(date_to)

        # Status (default available; allow ?status=rented or status=)
        if status:
            where.append("p.status = %s")
            params.append(status)

        where_sql = " AND ".join(where)
        if where_sql:
            where_sql = "WHERE " + where_sql

        # Build query (aggregate for rating filter)
        # NOTE: use HAVING for rating_min, since it's an aggregate.
        having_sql = ""
        having_params = []
        if rating_min:
            having_sql = "HAVING IFNULL(AVG(r.rating),0) >= %s"
            having_params.append(rating_min)

        sql = f"""
            SELECT 
                p.id, p.title, p.price_per_day, p.image_url, p.location,
                p.available_from, p.available_to, p.status,
                IFNULL(AVG(r.rating), 0) AS avg_rating,
                COUNT(r.id) AS rating_count
            FROM products p
            LEFT JOIN reviews r ON r.product_id = p.id
            {where_sql}
            GROUP BY p.id
            {having_sql}
            ORDER BY p.created_at DESC
        """

        cur = g.db.cursor(dictionary=True)
        cur.execute(sql, tuple(params + having_params))
        products = cur.fetchall()

    finally:
        if cur is not None:
            cur.close()

    # prettify availability
    for p in products:
        af = p.get("available_from")
        at = p.get("available_to")
        p["available_summary"] = f"{af} → {at}" if af and at else "Not specified"

    return render_template("dashboard.html", products=products)

@app.route("/products/<int:product_id>")
def product_details(product_id):
    # Product + owner info + ratings
    cur = g.db.cursor(dictionary=True)
    cur.execute("""
        SELECT 
            p.*, 
            u.name AS owner_name, u.phone AS owner_phone, u.email AS owner_email,
            IFNULL(AVG(r.rating), 0) AS avg_rating,
            COUNT(r.id) AS rating_count
        FROM products p
        JOIN users u ON p.owner_id = u.id
        LEFT JOIN reviews r ON p.id = r.product_id
        WHERE p.id = %s
    """, (product_id,))
    product = cur.fetchone()
    cur.close()

    if not product:
        flash("Product not found.")
        return redirect(url_for("dashboard"))

    # Load all reviews
    cur = g.db.cursor(dictionary=True)
    cur.execute("""
        SELECT r.*, u.name AS reviewer_name 
        FROM reviews r
        JOIN users u ON r.user_id = u.id
        WHERE r.product_id = %s
        ORDER BY r.created_at DESC
    """, (product_id,))
    reviews = cur.fetchall()
    cur.close()

    # Get current user's review if logged in
    user_review = None
    if "user_id" in session:
        cur = g.db.cursor(dictionary=True)
        cur.execute("SELECT * FROM reviews WHERE product_id=%s AND user_id=%s",
                    (product_id, session["user_id"]))
        user_review = cur.fetchone()
        cur.close()

    if product["available_from"] and product["available_to"]:
        product["available_summary"] = f"{product['available_from']} → {product['available_to']}"
    else:
        product["available_summary"] = "Not specified"

    return render_template("details.html",
                           product=product,
                           reviews=reviews,
                           user_review=user_review)


    # Load individual reviews (optional, if you want to display them)
    cur = g.db.cursor(dictionary=True)
    cur.execute("""
        SELECT r.*, u.name AS reviewer_name 
        FROM reviews r
        JOIN users u ON r.user_id = u.id
        WHERE r.product_id = %s
        ORDER BY r.created_at DESC
    """, (product_id,))
    reviews = cur.fetchall()
    cur.close()

    # Convert date range for display
    if product["available_from"] and product["available_to"]:
        product["available_summary"] = f"{product['available_from']} → {product['available_to']}"
    else:
        product["available_summary"] = "Not specified"

    return render_template("details.html", product=product, reviews=reviews)

@app.route("/user/<int:user_id>")
def view_owner(user_id):
    cur = g.db.cursor(dictionary=True)
    cur.execute("SELECT id, name, email, phone, nid, created_at FROM users WHERE id = %s", (user_id,))
    owner = cur.fetchone()
    cur.close()

    if not owner:
        flash("Owner not found.")
        return redirect(url_for("dashboard"))

    return render_template("owner.html", owner=owner, app_name="KhepGaming")


@app.route("/products/<int:product_id>/rate", methods=["POST"])
def rate_product(product_id):
    user_id = session.get("user_id")
    if not user_id:
        flash("Please log in first to rate.")
        return redirect(url_for("login"))

    rating = request.form.get("rating")
    comment = request.form.get("comment") or None

    try:
        rating = int(rating)
        if rating < 1 or rating > 5:
            raise ValueError
    except Exception:
        flash("Invalid rating.")
        return redirect(url_for("product_details", product_id=product_id))

    cur = g.db.cursor()
    cur.execute("""
        INSERT INTO reviews (product_id, user_id, rating, comment)
        VALUES (%s, %s, %s, %s)
        ON DUPLICATE KEY UPDATE
          rating = VALUES(rating),
          comment = VALUES(comment),
          created_at = NOW()
    """, (product_id, user_id, rating, comment))
    g.db.commit()
    cur.close()

    flash("Your review has been saved.")
    return redirect(url_for("product_details", product_id=product_id))



    flash("Thanks for your review!")
    return redirect(url_for("product_details", product_id=product_id))

from datetime import date

from datetime import date

@app.route("/rent/<int:product_id>/request", methods=["GET"])
def rent_request(product_id):
    # must be logged in
    uid = session.get("user_id")
    if not uid:
        flash("Please log in first.")
        return redirect(url_for("login"))

    cur = g.db.cursor(dictionary=True)
    cur.execute("""
        SELECT id, title, price_per_day, owner_id, image_url,
               available_from, available_to, status, location, description
        FROM products
        WHERE id=%s
    """, (product_id,))
    product = cur.fetchone()
    cur.close()

    if not product:
        flash("Product not found.")
        return redirect(url_for("dashboard"))

    if product["status"] != "available":
        flash("This product is not available right now.")
        return redirect(url_for("product_details", product_id=product_id))

    # compute max days from availability window
    af, at = product["available_from"], product["available_to"]
    if isinstance(af, str): af = date.fromisoformat(af)
    if isinstance(at, str): at = date.fromisoformat(at)
    max_days = max(1, (at - af).days + 1)

    return render_template(
        "rent.html",
        product=product,
        max_days=max_days,
        min_days=1
    )


from datetime import date
from decimal import Decimal, ROUND_HALF_UP

@app.route("/rent/<int:product_id>/confirm", methods=["POST"])
def rent_confirm(product_id):
    renter_id = session.get("user_id")
    if not renter_id:
        flash("Please log in first.")
        return redirect(url_for("login"))

    # Parse days
    try:
        days = int(request.form.get("days", "1"))
        if days < 1:
            raise ValueError
    except Exception:
        flash("Invalid number of days.")
        return redirect(url_for("rent_request", product_id=product_id))

    # Load product
    cur = g.db.cursor(dictionary=True)
    cur.execute("""
        SELECT id, title, price_per_day, owner_id, available_from, available_to, status
        FROM products WHERE id=%s
    """, (product_id,))
    product = cur.fetchone()

    if not product:
        cur.close()
        flash("Product not found.")
        return redirect(url_for("dashboard"))

    if product["status"] != "available":
        cur.close()
        flash("This product is no longer available.")
        return redirect(url_for("product_details", product_id=product_id))

    lister_id = product["owner_id"]
    if lister_id == renter_id:
        cur.close()
        flash("You cannot rent your own product.")
        return redirect(url_for("product_details", product_id=product_id))

    # Calculate totals
    from datetime import date
    from decimal import Decimal, ROUND_HALF_UP
    af, at = product["available_from"], product["available_to"]
    if isinstance(af, str): af = date.fromisoformat(af)
    if isinstance(at, str): at = date.fromisoformat(at)
    max_days = max(1, (at - af).days + 1)
    if days > max_days:
        cur.close()
        flash(f"Max {max_days} day(s) allowed for this item based on availability.")
        return redirect(url_for("rent_request", product_id=product_id))

    price_per_day = Decimal(str(product["price_per_day"]))
    total = (price_per_day * days).quantize(Decimal("0.01"), rounding=ROUND_HALF_UP)
    platform_fee = (total * Decimal("0.15")).quantize(Decimal("0.01"), rounding=ROUND_HALF_UP)
    lister_earnings = (total - platform_fee).quantize(Decimal("0.01"), rounding=ROUND_HALF_UP)

    # Lock renter & lister wallets
    cur.execute("SELECT id, wallet FROM users WHERE id=%s FOR UPDATE", (renter_id,))
    renter = cur.fetchone()
    cur.execute("SELECT id, wallet FROM users WHERE id=%s FOR UPDATE", (lister_id,))
    lister = cur.fetchone()

    if Decimal(str(renter["wallet"])) < total:
        cur.close()
        return render_template("nonsuff.html", product_id=product_id)

    try:
        # Deduct renter
        cur.execute("UPDATE users SET wallet = wallet - %s WHERE id = %s", (total, renter_id))

        # Credit lister (85%)
        cur.execute("UPDATE users SET wallet = wallet + %s WHERE id = %s", (lister_earnings, lister_id))

        # 💰 Credit admin wallet (15%)
        cur.execute("UPDATE admin_wallet SET balance = balance + %s WHERE id = 1", (platform_fee,))

        # Record booking
        cur.execute("""
            INSERT INTO bookings (product_id, renter_id, lister_id, days, price_per_day, total_amount, platform_fee, lister_earnings)
            VALUES (%s,%s,%s,%s,%s,%s,%s,%s)
        """, (product_id, renter_id, lister_id, days, price_per_day, total, platform_fee, lister_earnings))

        # Mark product rented
        cur.execute("UPDATE products SET status = 'rented' WHERE id = %s", (product_id,))

        g.db.commit()
        flash("Rental confirmed! Enjoy your item.")
    except Exception as e:
        g.db.rollback()
        flash("Could not complete the rental. Please try again.")
    finally:
        cur.close()

    return redirect(url_for("product_details", product_id=product_id))

# =======================
# Admin utilities
# =======================
from functools import wraps

def admin_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if not session.get("admin_id"):
            flash("Please log in as admin.")
            return redirect(url_for("admin_login_page"))
        return f(*args, **kwargs)
    return wrapper


# =======================
# Admin Home
# =======================
@app.route("/admin/home")
@admin_required
def admin_home():
    cur = None
    try:
        # admin info
        cur = g.db.cursor(dictionary=True)
        cur.execute("SELECT id, name, email, phone, created_at FROM admins WHERE id=%s", (session["admin_id"],))
        admin = cur.fetchone()
        cur.close(); cur = None

        # shared wallet
        cur = g.db.cursor(dictionary=True)
        cur.execute("SELECT balance FROM admin_wallet WHERE id = 1")
        admin_wallet = cur.fetchone() or {"balance": 0}
    finally:
        if cur is not None:
            cur.close()

    return render_template("admin_home.html", admin=admin, admin_wallet=admin_wallet)


# =======================
# Admin Users (list + search)
# =======================
@app.route("/admin/users")
@admin_required
def admin_users():
    q = (request.args.get("q") or "").strip()
    cur = None
    try:
        cur = g.db.cursor(dictionary=True)
        if q:
            like = f"%{q}%"
            cur.execute("""
                SELECT id, name, email, phone, created_at, is_suspended
                FROM users
                WHERE name LIKE %s OR email LIKE %s OR phone LIKE %s
                ORDER BY created_at DESC
            """, (like, like, like))
        else:
            cur.execute("""
                SELECT id, name, email, phone, created_at, is_suspended
                FROM users
                ORDER BY created_at DESC
            """)
        users = cur.fetchall()
    finally:
        if cur is not None:
            cur.close()
    return render_template("admin_users.html", users=users, q=q)

@app.route("/admin/users/<int:user_id>/suspend", methods=["POST"])
@admin_required
def admin_suspend_user(user_id):
    cur = None
    try:
        cur = g.db.cursor()
        cur.execute("UPDATE users SET is_suspended=1 WHERE id=%s", (user_id,))
        g.db.commit()
        flash("User suspended.")
    except Exception:
        g.db.rollback()
        flash("Could not suspend user.")
    finally:
        if cur is not None:
            cur.close()
    return redirect(url_for("admin_users"))

@app.route("/admin/users/<int:user_id>/unsuspend", methods=["POST"])
@admin_required
def admin_unsuspend_user(user_id):
    cur = None
    try:
        cur = g.db.cursor()
        cur.execute("UPDATE users SET is_suspended=0 WHERE id=%s", (user_id,))
        g.db.commit()
        flash("User unsuspended.")
    except Exception:
        g.db.rollback()
        flash("Could not unsuspend user.")
    finally:
        if cur is not None:
            cur.close()
    return redirect(url_for("admin_users"))


# =======================
# Admin Bookings (list + search + cancel)
# =======================
# LIST confirmed bookings
@app.route("/admin/bookings")
@admin_required
def admin_bookings():
    cur = g.db.cursor(dictionary=True)
    cur.execute("""
        SELECT 
          b.id, b.product_id, b.renter_id, b.lister_id, b.days, b.price_per_day,
          b.total_amount, b.platform_fee, b.lister_earnings, b.created_at,
          p.title AS product_title,
          ru.name AS renter_name, ru.phone AS renter_phone,
          lu.name AS lister_name, lu.phone AS lister_phone
        FROM bookings b
        JOIN products p ON p.id = b.product_id
        JOIN users ru ON ru.id = b.renter_id
        JOIN users lu ON lu.id = b.lister_id
        WHERE b.status = 'confirmed'
        ORDER BY b.created_at DESC
    """)
    rows = cur.fetchall()
    cur.close()
    return render_template("admin_bookings.html", bookings=rows)

@app.route("/admin/bookings/<int:booking_id>/cancel", methods=["POST"])
@admin_required
def admin_cancel_booking(booking_id):
    """
    Admin cancellation policy:
      - Renter gets 100% refund (total_amount)
      - Admin wallet is deducted by platform_fee (15%)
      - Lister wallet is deducted by lister_earnings (85%)
      - Booking status -> 'cancelled'
      - Product status -> 'available'
    """
    cur = None
    try:
        cur = g.db.cursor(dictionary=True)

        # 1) Load booking (must be confirmed)
        cur.execute("""
            SELECT b.*, p.status AS product_status
            FROM bookings b
            JOIN products p ON p.id = b.product_id
            WHERE b.id = %s AND b.status = 'confirmed'
        """, (booking_id,))
        b = cur.fetchone()
        if not b:
            flash("Booking not found or already cancelled.")
            return redirect(url_for("admin_bookings"))

        product_id   = b["product_id"]
        renter_id    = b["renter_id"]
        lister_id    = b["lister_id"]
        total_amount = b["total_amount"]
        platform_fee = b["platform_fee"]
        lister_take  = b["lister_earnings"]

        # 2) Lock admin wallet + wallets of renter & lister for consistency
        cur.execute("SELECT id, balance FROM admin_wallet WHERE id = 1 FOR UPDATE")
        admin_w = cur.fetchone()
        cur.execute("SELECT id, wallet FROM users WHERE id=%s FOR UPDATE", (renter_id,))
        renter = cur.fetchone()
        cur.execute("SELECT id, wallet FROM users WHERE id=%s FOR UPDATE", (lister_id,))
        lister = cur.fetchone()

        # 3) Check balances are sufficient to roll back
        #    - admin must have >= platform_fee
        #    - lister must have >= lister_earnings
        from decimal import Decimal
        if Decimal(str(admin_w["balance"])) < Decimal(str(platform_fee)):
            flash("Cannot cancel: admin wallet has insufficient balance to return the platform fee.")
            return redirect(url_for("admin_bookings"))
        if Decimal(str(lister["wallet"])) < Decimal(str(lister_take)):
            flash("Cannot cancel: lister has insufficient balance to return earnings.")
            return redirect(url_for("admin_bookings"))

        # 4) Perform atomic updates
        try:
            # Deduct from admin wallet (15%)
            cur.execute("UPDATE admin_wallet SET balance = balance - %s WHERE id = 1", (platform_fee,))
            # Deduct from lister (85%)
            cur.execute("UPDATE users SET wallet = wallet - %s WHERE id = %s", (lister_take, lister_id))
            # Refund renter (100%)
            cur.execute("UPDATE users SET wallet = wallet + %s WHERE id = %s", (total_amount, renter_id))
            # Mark booking cancelled
            cur.execute("UPDATE bookings SET status='cancelled' WHERE id=%s", (booking_id,))
            # Reopen the product for renting
            cur.execute("UPDATE products SET status='available' WHERE id=%s", (product_id,))

            g.db.commit()
            flash("Booking cancelled. Full refund sent to renter; lister/admin deductions applied.")
        except Exception:
            g.db.rollback()
            flash("Could not cancel booking due to an internal error. No changes were made.")
    finally:
        if cur is not None:
            cur.close()

    return redirect(url_for("admin_bookings"))



# =======================
# Admin Rentals (list + search + delete product)
# =======================
@app.route("/admin/rentals")
@admin_required
def admin_rentals():
    q = (request.args.get("q") or "").strip()
    cur = None
    try:
        cur = g.db.cursor(dictionary=True)
        if q:
            like = f"%{q}%"
            cur.execute("""
                SELECT p.id, p.title, p.image_url, p.price_per_day, p.status, p.created_at,
                       p.owner_id, u.name AS owner_name
                FROM products p
                JOIN users u ON p.owner_id = u.id
                WHERE p.title LIKE %s OR u.name LIKE %s OR p.status LIKE %s OR p.id LIKE %s
                ORDER BY p.created_at DESC
            """, (like, like, like, like))
        else:
            cur.execute("""
                SELECT p.id, p.title, p.image_url, p.price_per_day, p.status, p.created_at,
                       p.owner_id, u.name AS owner_name
                FROM products p
                JOIN users u ON p.owner_id = u.id
                ORDER BY p.created_at DESC
            """)
        products = cur.fetchall()
    finally:
        if cur is not None:
            cur.close()
    return render_template("admin_rentals.html", products=products, q=q)

@app.route("/admin/products/<int:product_id>/delete", methods=["POST"])
@admin_required
def admin_delete_product(product_id):
    cur = None
    try:
        cur = g.db.cursor()
        cur.execute("DELETE FROM products WHERE id=%s", (product_id,))
        g.db.commit()
        flash("Product deleted.")
    except Exception:
        g.db.rollback()
        flash("Could not delete product.")
    finally:
        if cur is not None:
            cur.close()
    return redirect(url_for("admin_rentals"))

from decimal import Decimal, ROUND_HALF_UP

@app.route("/me/booked")
def my_booked():
    uid = session.get("user_id")
    if not uid:
        flash("Please log in first.")
        return redirect(url_for("login"))

    q = (request.args.get("q") or "").strip()
    cur = g.db.cursor(dictionary=True)
    if q:
        like = f"%{q}%"
        cur.execute("""
            SELECT b.*, p.title AS product_title
            FROM bookings b
            JOIN products p ON b.product_id = p.id
            WHERE b.renter_id = %s
              AND (p.title LIKE %s OR b.id LIKE %s)
            ORDER BY b.created_at DESC
        """, (uid, like, like))
    else:
        cur.execute("""
            SELECT b.*, p.title AS product_title
            FROM bookings b
            JOIN products p ON b.product_id = p.id
            WHERE b.renter_id = %s
            ORDER BY b.created_at DESC
        """, (uid,))
    bookings = cur.fetchall()
    cur.close()

    return render_template("my_booked.html", bookings=bookings, q=q)

@app.route("/me/bookings/<int:booking_id>/cancel", methods=["POST"])
def my_cancel_booking(booking_id):
    uid = session.get("user_id")
    if not uid:
        flash("Please log in first.")
        return redirect(url_for("login"))

    cur = g.db.cursor(dictionary=True)
    # Load booking (must belong to this renter and not cancelled)
    cur.execute("""
        SELECT * FROM bookings
        WHERE id=%s AND renter_id=%s AND status='confirmed'
        """, (booking_id, uid))
    b = cur.fetchone()
    if not b:
        cur.close()
        flash("Booking not found or already cancelled.")
        return redirect(url_for("my_booked"))

    # Compute refund = 50% of total
    total = Decimal(str(b["total_amount"]))
    refund = (total * Decimal("0.50")).quantize(Decimal("0.01"), rounding=ROUND_HALF_UP)

    # Check lister has enough to cover refund (simple rule)
    cur.execute("SELECT id, wallet FROM users WHERE id=%s FOR UPDATE", (b["lister_id"],))
    lister = cur.fetchone()
    cur.execute("SELECT id, wallet FROM users WHERE id=%s FOR UPDATE", (b["renter_id"],))
    renter = cur.fetchone()

    if Decimal(str(lister["wallet"])) < refund:
        cur.close()
        flash("Unable to cancel now: lister does not have sufficient balance for refund.")
        return redirect(url_for("my_booked"))

    try:
        # Move 50% from lister to renter
        cur.execute("UPDATE users SET wallet = wallet - %s WHERE id=%s", (refund, b["lister_id"]))
        cur.execute("UPDATE users SET wallet = wallet + %s WHERE id=%s", (refund, b["renter_id"]))
        # Mark booking cancelled
        cur.execute("UPDATE bookings SET status='cancelled' WHERE id=%s", (booking_id,))
        g.db.commit()
        flash(f"Booking cancelled. Refunded {refund} BDT.")
    except Exception:
        g.db.rollback()
        flash("Could not cancel the booking. Please try again.")
    finally:
        cur.close()

    return redirect(url_for("my_booked"))

@app.route("/me/rented")
def my_rented():
    uid = session.get("user_id")
    if not uid:
        flash("Please log in first.")
        return redirect(url_for("login"))

    q = (request.args.get("q") or "").strip()
    cur = g.db.cursor(dictionary=True)
    if q:
        like = f"%{q}%"
        cur.execute("""
            SELECT id, title, image_url, price_per_day, status, created_at
            FROM products
            WHERE owner_id = %s
              AND (title LIKE %s OR status LIKE %s)
            ORDER BY created_at DESC
        """, (uid, like, like))
    else:
        cur.execute("""
            SELECT id, title, image_url, price_per_day, status, created_at
            FROM products
            WHERE owner_id = %s
            ORDER BY created_at DESC
        """, (uid,))
    products = cur.fetchall()
    cur.close()

    return render_template("my_rented.html", products=products, q=q)


@app.route("/me/products/<int:product_id>/delete", methods=["POST"])
def my_delete_listing(product_id):
    uid = session.get("user_id")
    if not uid:
        flash("Please log in first.")
        return redirect(url_for("login"))

    cur = g.db.cursor(dictionary=True)
    # Only allow deleting your own product that is still available
    cur.execute("SELECT id, owner_id, status FROM products WHERE id=%s", (product_id,))
    p = cur.fetchone()
    if not p or p["owner_id"] != uid:
        cur.close()
        flash("Product not found.")
        return redirect(url_for("my_rented"))

    if p["status"] != "available":
        cur.close()
        flash("Cannot remove: product already rented.")
        return redirect(url_for("my_rented"))

    try:
        cur.execute("DELETE FROM products WHERE id=%s", (product_id,))
        g.db.commit()
        flash("Listing removed.")
    except Exception:
        g.db.rollback()
        flash("Could not remove the listing.")
    finally:
        cur.close()

    return redirect(url_for("my_rented"))


# ----------------------------
# Main
# ----------------------------
if __name__ == "__main__":
    app.run(port=8000, debug=True)
    
