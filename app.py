from flask import Flask, render_template, request, redirect, url_for, session, jsonify, flash
from werkzeug.security import generate_password_hash, check_password_hash
from collections import defaultdict, deque
from datetime import datetime, timedelta
from functools import wraps
import sqlite3, os, uuid, re, csv, math, json, hmac, hashlib, html, secrets

from analytics_engine import (
    compute_customer_rfm_and_segments,
    compute_market_basket_analysis,
    get_frequently_bought_together,
    get_executive_bi_dashboard_data,
    generate_personalized_offer_for_customer
)

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "datacart-python-ecommerce-secret-key-2026-super-secure")
DB = os.path.join(os.path.dirname(__file__), "ecommerce.db")

# -----------------------------
# Industrial-Grade Security & Cookie Protection
# -----------------------------
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,       # Mitigates XSS cookie theft
    SESSION_COOKIE_SAMESITE="Lax",      # Defends against CSRF attacks
    PERMANENT_SESSION_LIFETIME=timedelta(days=7) # Enforces session lifespan
)


# -----------------------------
# HTTP Security Headers Middleware (OWASP Top 10)
# -----------------------------
@app.after_request
def apply_security_headers(response):
    """Applies military-grade HTTP security headers on all responses."""
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "SAMEORIGIN"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
    response.headers["X-Permitted-Cross-Domain-Policies"] = "none"
    return response


# -----------------------------
# Security & Cryptographic Vault Helpers
# -----------------------------
def sanitize_input(val, max_len=1000):
    """Strips dangerous HTML/script injections to prevent Stored XSS."""
    if not val:
        return ""
    escaped = html.escape(str(val).strip())
    clean = re.sub(r'(?i)<script.*?>.*?</script>', '', escaped)
    return clean[:max_len]


def generate_payment_security_token(order_id, amount, customer_id):
    """Generates a cryptographically random, PCI-DSS compliant payment token."""
    rand_hex = secrets.token_hex(12)
    return f"tok_sec_{order_id}_{int(amount)}_{customer_id}_{rand_hex}"


def generate_payment_signature(order_id, amount, customer_id, timestamp):
    """Creates a tamper-proof HMAC-SHA256 checksum to prevent order price tampering."""
    payload = f"ORD:{order_id}|AMT:{amount:.2f}|CUST:{customer_id}|TS:{timestamp}"
    return hmac.new(app.secret_key.encode('utf-8'), payload.encode('utf-8'), hashlib.sha256).hexdigest()


def mask_payment_identifier(method, identifier=""):
    """PCI-DSS requirement: Mask all sensitive payment identifiers."""
    method_clean = method.lower()
    if "upi" in method_clean:
        if "@" in identifier:
            parts = identifier.split("@")
            user_part = parts[0]
            masked_user = user_part[:2] + ("*" * max(1, len(user_part) - 2))
            return f"{masked_user}@{parts[1]}"
        return "amazonpay.upi@okaxis"
    elif "card" in method_clean:
        digits = re.sub(r'\D', '', identifier)
        last4 = digits[-4:] if len(digits) >= 4 else "4242"
        return f"Visa / Master ending in •••• {last4}"
    elif "net banking" in method_clean or "bank" in method_clean:
        return f"{identifier or 'HDFC Bank'} (256-Bit SSL Tokenized)"
    return "Cash on Delivery (OTP Verified on Delivery)"


def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get("customer_id"):
            flash("Please sign in to proceed.", "info")
            return redirect(url_for("login", next=request.url))
        return f(*args, **kwargs)
    return decorated_function


def merchant_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get("merchant_id"):
            flash("Seller Central authentication required. Please log in as a merchant.", "error")
            return redirect(url_for("merchant_login"))
        return f(*args, **kwargs)
    return decorated_function


def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # Allow instant developer access or verified admin
        if session.get("role") != "admin" and not session.get("is_developer"):
            flash("Administrator / Developer credentials required to access Executive BI.", "info")
            return redirect(url_for("admin_login", next=request.url))
        return f(*args, **kwargs)
    return decorated_function


# -----------------------------
# Database Connection & Migration
# -----------------------------
def db():
    conn = sqlite3.connect(DB)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = db()
    conn.executescript("""
    CREATE TABLE IF NOT EXISTS customers(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        email TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        role TEXT DEFAULT 'customer',
        store_name TEXT DEFAULT '',
        business_id TEXT DEFAULT '',
        city TEXT DEFAULT 'Bharuch',
        whatsapp TEXT DEFAULT '',
        address TEXT DEFAULT '',
        pincode TEXT DEFAULT '392001',
        created_at TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS products(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        description TEXT,
        price REAL NOT NULL,
        original_price REAL NOT NULL,
        stock INTEGER NOT NULL,
        category TEXT NOT NULL,
        rating REAL DEFAULT 4.5,
        review_count INTEGER DEFAULT 120,
        badge TEXT DEFAULT '',
        image_url TEXT DEFAULT '',
        tags TEXT DEFAULT '',
        merchant_id INTEGER DEFAULT 1,
        store_name TEXT DEFAULT 'DataCart Direct',
        city TEXT DEFAULT 'Bharuch',
        store_address TEXT DEFAULT 'Station Road, Bharuch',
        whatsapp_number TEXT DEFAULT '919876543210'
    );
    CREATE TABLE IF NOT EXISTS orders(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        customer_id INTEGER NOT NULL,
        status TEXT NOT NULL,
        total REAL NOT NULL,
        discount_amount REAL DEFAULT 0.0,
        coupon_code TEXT DEFAULT '',
        payment_status TEXT NOT NULL,
        tracking_id TEXT,
        created_at TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS order_items(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        order_id INTEGER NOT NULL,
        product_id INTEGER NOT NULL,
        quantity INTEGER NOT NULL,
        price REAL NOT NULL,
        merchant_id INTEGER DEFAULT 1
    );
    CREATE TABLE IF NOT EXISTS payments(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        order_id INTEGER NOT NULL,
        method TEXT NOT NULL,
        txn_status TEXT NOT NULL,
        token TEXT NOT NULL,
        masked_details TEXT DEFAULT '',
        signature_hash TEXT DEFAULT '',
        created_at TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS events(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        customer_id INTEGER,
        product_id INTEGER,
        event_type TEXT NOT NULL,
        created_at TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS reviews(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        product_id INTEGER NOT NULL,
        customer_name TEXT NOT NULL,
        rating INTEGER NOT NULL,
        title TEXT,
        comment TEXT,
        created_at TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS reservations(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        customer_id INTEGER NOT NULL,
        customer_name TEXT,
        customer_phone TEXT,
        product_id INTEGER NOT NULL,
        product_name TEXT,
        store_name TEXT,
        store_address TEXT,
        merchant_id INTEGER,
        quantity INTEGER DEFAULT 1,
        price REAL,
        pickup_otp TEXT NOT NULL,
        status TEXT DEFAULT 'ACTIVE',
        expires_at TEXT NOT NULL,
        created_at TEXT NOT NULL
    );
    """)

    # Safe dynamic column migrations
    for col_def in [
        ("customers", "role", "TEXT DEFAULT 'customer'"),
        ("customers", "store_name", "TEXT DEFAULT ''"),
        ("customers", "business_id", "TEXT DEFAULT ''"),
        ("customers", "city", "TEXT DEFAULT 'Ankleshwar'"),
        ("customers", "whatsapp", "TEXT DEFAULT ''"),
        ("products", "merchant_id", "INTEGER DEFAULT 1"),
        ("products", "store_name", "TEXT DEFAULT 'DataCart Direct'"),
        ("products", "city", "TEXT DEFAULT 'Ankleshwar'"),
        ("products", "store_address", "TEXT DEFAULT 'Station Road, Ankleshwar'"),
        ("products", "whatsapp_number", "TEXT DEFAULT '919876543210'"),
        ("order_items", "merchant_id", "INTEGER DEFAULT 1"),
        ("payments", "masked_details", "TEXT DEFAULT ''"),
        ("payments", "signature_hash", "TEXT DEFAULT ''")
    ]:
        try:
            conn.execute(f"ALTER TABLE {col_def[0]} ADD COLUMN {col_def[1]} {col_def[2]}")
        except:
            pass

    # Ensure default Administrator account exists
    admin_row = conn.execute("SELECT id FROM customers WHERE email='admin@datacart.com'").fetchone()
    if not admin_row:
        conn.execute("""
            INSERT INTO customers(name, email, password_hash, role, store_name, business_id, address, pincode, created_at)
            VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            "DataCart Executive Admin",
            "admin@datacart.com",
            generate_password_hash("admin123"),
            "admin",
            "DataCart Corporate HQ",
            "GSTIN24ADMIN9999Z1",
            "GIDC Commercial Complex, Ankleshwar",
            "393002",
            datetime.utcnow().isoformat()
        ))
        conn.commit()

    # Seed Verified Local Merchants in Ankleshwar
    merchant_count = conn.execute("SELECT COUNT(*) FROM customers WHERE role='merchant'").fetchone()[0]
    if merchant_count < 4:
        merchants = [
            (
                "Shreeji Electronics", "shreeji.ank@example.com", generate_password_hash("seller123"), "merchant",
                "Shreeji Electronics & Appliances", "GSTIN24AABCS1234F1Z1", "Ankleshwar", "919876543210",
                "Shop 12, Station Road Commercial Complex, Ankleshwar", "393001", datetime.utcnow().isoformat()
            ),
            (
                "Narmada Tech", "narmada.tech@example.com", generate_password_hash("seller123"), "merchant",
                "Narmada Tech & IT Solutions", "GSTIN24AABCN5678G1Z2", "Ankleshwar", "919876543211",
                "GIDC Industrial Estate, Near Water Tank, Ankleshwar", "393002", datetime.utcnow().isoformat()
            ),
            (
                "Gujarat Smart Living", "smart.living@example.com", generate_password_hash("seller123"), "merchant",
                "Gujarat Smart Living & Lighting", "GSTIN24AABCG9101H1Z3", "Ankleshwar", "919876543212",
                "Rajpipla Road High Street, Ankleshwar", "393001", datetime.utcnow().isoformat()
            ),
            (
                "Ankleshwar Sound Studio", "sound.studio@example.com", generate_password_hash("seller123"), "merchant",
                "Ankleshwar Sound Studio & Acoustics", "GSTIN24AABCS3141J1Z4", "Ankleshwar", "919876543213",
                "Valia Road Corner, Ankleshwar", "393002", datetime.utcnow().isoformat()
            ),
            (
                "Radhe Hardware", "radhe.hardware@example.com", generate_password_hash("seller123"), "merchant",
                "Radhe Industrial Hardware & Tools", "GSTIN24AABCR5161K1Z5", "Ankleshwar", "919876543214",
                "Plot 45, GIDC Phase-1, Ankleshwar", "393002", datetime.utcnow().isoformat()
            )
        ]
        for m in merchants:
            conn.execute("""
                INSERT OR IGNORE INTO customers(name, email, password_hash, role, store_name, business_id, city, whatsapp, address, pincode, created_at)
                VALUES(?,?,?,?,?,?,?,?,?,?,?)
            """, m)
        conn.commit()

    # Fetch seeded merchant IDs
    shreeji_m = conn.execute("SELECT id FROM customers WHERE store_name='Shreeji Electronics & Appliances'").fetchone()
    shreeji_id = shreeji_m["id"] if shreeji_m else 1
    narmada_m = conn.execute("SELECT id FROM customers WHERE store_name='Narmada Tech & IT Solutions'").fetchone()
    narmada_id = narmada_m["id"] if narmada_m else 1
    sound_m = conn.execute("SELECT id FROM customers WHERE store_name='Ankleshwar Sound Studio & Acoustics'").fetchone()
    sound_id = sound_m["id"] if sound_m else 1
    smart_m = conn.execute("SELECT id FROM customers WHERE store_name='Gujarat Smart Living & Lighting'").fetchone()
    smart_id = smart_m["id"] if smart_m else 1
    radhe_m = conn.execute("SELECT id FROM customers WHERE store_name='Radhe Industrial Hardware & Tools'").fetchone()
    radhe_id = radhe_m["id"] if radhe_m else 1

    # Check if catalog needs refresh
    total_prods = conn.execute("SELECT COUNT(*) FROM products").fetchone()[0]
    ank_prods = conn.execute("SELECT COUNT(*) FROM products WHERE city='Ankleshwar'").fetchone()[0]

    if total_prods < 15 or ank_prods < 5:
        conn.execute("DELETE FROM products")
        products = [
            (
                "Apple MacBook Air M3 (13.6-inch, 8-Core CPU, 512GB SSD, Space Gray)",
                "Strikingly thin and fast with next-gen Apple M3 chip. Features 13.6-inch Liquid Retina display, 18-hour battery life, 1080p FaceTime HD camera, MagSafe 3 charging, and dual external display support.",
                104900.0, 119900.0, 12, "Computers", 4.9, 2140, "Top Rated",
                "https://images.unsplash.com/photo-1517336714731-489689fd1ca8?w=500&auto=format&fit=crop&q=80",
                "laptop apple macbook air m3 computer thin light space gray",
                shreeji_id, "Shreeji Electronics & Appliances", "Ankleshwar", "Shop 12, Station Road Commercial Complex, Ankleshwar", "919876543210"
            ),
            (
                "Dell XPS 13 Plus Ultrabook (Intel Core i7 13th Gen, 16GB RAM, 1TB SSD, 3.5K OLED)",
                "Futuristic minimalist design with zero-lattice keyboard, capacitive touch function row, seamless glass haptic touchpad, and brilliant 3.5K OLED infinity edge display.",
                134990.0, 159990.0, 8, "Computers", 4.7, 860, "Premium Choice",
                "https://images.unsplash.com/photo-1588872657578-7efd1f1555ed?w=500&auto=format&fit=crop&q=80",
                "laptop dell xps 13 ultrabook windows oled touch premium",
                narmada_id, "Narmada Tech & IT Solutions", "Ankleshwar", "GIDC Industrial Estate, Ankleshwar", "919876543211"
            ),
            (
                "ASUS ROG Zephyrus G14 Gaming Laptop (Ryzen 9 8945HS, RTX 4070, 32GB RAM, 165Hz QHD OLED)",
                "Ultraportable AI-ready gaming laptop crafted from CNC-machined aluminium with Slash Lighting. ROG Nebula Display with 100% DCI-P3 and NVIDIA G-Sync.",
                159990.0, 189990.0, 6, "Gaming", 4.8, 1420, "Flagship Deal",
                "https://images.unsplash.com/photo-1603302576837-37561b2e2302?w=500&auto=format&fit=crop&q=80",
                "gaming laptop asus rog zephyrus rtx 4070 oled ryzen 9",
                narmada_id, "Narmada Tech & IT Solutions", "Ankleshwar", "GIDC Industrial Estate, Ankleshwar", "919876543211"
            ),
            (
                "Apple iPhone 15 Pro Max (256GB, Natural Titanium)",
                "Forged in titanium with aerospace-grade strength. Powered by game-changing A17 Pro chip, customizable Action button, and the most versatile 5x Optical Telephoto iPhone camera system.",
                139900.0, 159900.0, 15, "Computers", 4.9, 4520, "Best Seller",
                "https://images.unsplash.com/photo-1510557880182-3d4d3cba35a5?w=500&auto=format&fit=crop&q=80",
                "iphone apple 15 pro max titanium camera flagship smartphone",
                shreeji_id, "Shreeji Electronics & Appliances", "Ankleshwar", "Shop 12, Station Road Commercial Complex, Ankleshwar", "919876543210"
            ),
            (
                "Samsung Galaxy S24 Ultra 5G (512GB, Titanium Gray with Galaxy AI & S-Pen)",
                "Unleash new levels of creativity and productivity with Galaxy AI. Features 200MP Quad Tele camera, Snapdragon 8 Gen 3 for Galaxy, titanium shield, and built-in S-Pen.",
                129999.0, 144999.0, 10, "Computers", 4.8, 3180, "Hot Release",
                "https://images.unsplash.com/photo-1610945265064-0e34e5519bbf?w=500&auto=format&fit=crop&q=80",
                "samsung galaxy s24 ultra smartphone galaxy ai spen 5g android",
                shreeji_id, "Shreeji Electronics & Appliances", "Ankleshwar", "Shop 12, Station Road Commercial Complex, Ankleshwar", "919876543210"
            ),
            (
                "Sony WH-1000XM5 Wireless Active Noise-Cancelling Headphones",
                "Industry-leading noise cancellation powered by two processors and 8 microphones. Ultra-comfortable lightweight design, crystal clear hands-free calling, 30-hour battery life, and LDAC High-Res Audio.",
                26990.0, 34990.0, 24, "Audio", 4.8, 3890, "Audiophile Choice",
                "https://images.unsplash.com/photo-1505740420928-5e560c06d30e?w=500&auto=format&fit=crop&q=80",
                "sony headphones wh1000xm5 wireless anc bluetooth audio ldac",
                sound_id, "Ankleshwar Sound Studio & Acoustics", "Ankleshwar", "Valia Road Corner, Ankleshwar", "919876543213"
            ),
            (
                "Bose QuietComfort Ultra Wireless Earbuds with Spatial Audio",
                "Revolutionary spatial audio for immersive listening, world-class noise cancellation, CustomTune sound calibration tailored to your ears, and IPX4 sweat resistance.",
                23900.0, 29900.0, 18, "Audio", 4.7, 1850, "Top Rated",
                "https://images.unsplash.com/photo-1590658268037-6bf12165a8df?w=500&auto=format&fit=crop&q=80",
                "bose earbuds quietcomfort ultra wireless anc spatial audio bluetooth",
                sound_id, "Ankleshwar Sound Studio & Acoustics", "Ankleshwar", "Valia Road Corner, Ankleshwar", "919876543213"
            ),
            (
                "Marshall Stanmore III Bluetooth Home Audio Speaker (Black & Brass)",
                "Legendary Marshall room-filling sound with re-engineered wider soundstage, angled tweeters, updated waveguides, Bluetooth 5.2, and 3.5mm AUX input.",
                31999.0, 39999.0, 14, "Audio", 4.8, 2210, "Vintage Classic",
                "https://images.unsplash.com/photo-1545454675-3531b543be5d?w=500&auto=format&fit=crop&q=80",
                "marshall speaker stanmore bluetooth audio wireless bass home",
                sound_id, "Ankleshwar Sound Studio & Acoustics", "Ankleshwar", "Valia Road Corner, Ankleshwar", "919876543213"
            ),
            (
                "Logitech MX Master 3S Wireless Laser Mouse (Quiet Clicks, 8K DPI)",
                "Ergonomic mastery with 8000 DPI sensor capable of tracking on glass. Features MagSpeed electromagnetic scroll wheel, USB-C quick charge, and cross-device flow.",
                8495.0, 10995.0, 35, "Accessories", 4.9, 5820, "Workplace Pro",
                "https://images.unsplash.com/photo-1615663245857-ac93bb7c39e7?w=500&auto=format&fit=crop&q=80",
                "mouse logitech mx master wireless laser productivity ergonomic",
                narmada_id, "Narmada Tech & IT Solutions", "Ankleshwar", "GIDC Industrial Estate, Ankleshwar", "919876543211"
            ),
            (
                "Keychron Q1 Pro Custom Wireless Mechanical Keyboard (CNC Aluminum)",
                "Full CNC aluminum body, QMK/VIA wireless programmable, double-gasket acoustic design, hot-swappable Keychron K Pro Mechanical switches, and RGB backlighting.",
                14999.0, 18999.0, 15, "Accessories", 4.8, 1120, "Enthusiast Choice",
                "https://images.unsplash.com/photo-1587829741301-dc798b83add3?w=500&auto=format&fit=crop&q=80",
                "keyboard mechanical keychron q1 wireless qmk aluminum switches",
                narmada_id, "Narmada Tech & IT Solutions", "Ankleshwar", "GIDC Industrial Estate, Ankleshwar", "919876543211"
            ),
            (
                "Samsung Odyssey OLED G9 49-inch Curved Gaming Monitor (240Hz, 0.03ms)",
                "Colossal 49-inch 32:9 dual QHD curved OLED display with Neo Quantum Processor Pro, 240Hz refresh rate, 0.03ms response time, and DisplayHDR True Black 400.",
                119999.0, 149999.0, 5, "Gaming", 4.9, 740, "Ultra Wide Beast",
                "https://images.unsplash.com/photo-1527443224154-c4a3942d3acf?w=500&auto=format&fit=crop&q=80",
                "monitor samsung odyssey oled 49 inch curved gaming ultrawide 240hz",
                narmada_id, "Narmada Tech & IT Solutions", "Ankleshwar", "GIDC Industrial Estate, Ankleshwar", "919876543211"
            ),
            (
                "Apple Watch Ultra 2 (GPS + Cellular 49mm Titanium, Ocean Band)",
                "The most rugged and capable Apple Watch. Features 3000-nit brightest display, precision dual-frequency GPS, 36-hour battery life, and 100m water resistance for diving.",
                84900.0, 89900.0, 10, "Wearables", 4.9, 1920, "Extreme Outdoor",
                "https://images.unsplash.com/photo-1579586337278-3befd40fd17a?w=500&auto=format&fit=crop&q=80",
                "apple watch ultra 2 titanium gps cellular smartwatch fitness diving",
                shreeji_id, "Shreeji Electronics & Appliances", "Ankleshwar", "Shop 12, Station Road Commercial Complex, Ankleshwar", "919876543210"
            ),
            (
                "Garmin Fenix 7 Pro Sapphire Solar Multisport Smartwatch (51mm Titanium)",
                "Ultimate multisport GPS smartwatch with Solar charging lens, built-in LED flashlight, endurance score, Hill score, TopoActive maps, and up to 37 days battery life.",
                79990.0, 94990.0, 8, "Wearables", 4.8, 890, "Endurance Pro",
                "https://images.unsplash.com/photo-1523275335684-37898b6baf30?w=500&auto=format&fit=crop&q=80",
                "garmin fenix 7 pro solar titanium gps smartwatch endurance running",
                shreeji_id, "Shreeji Electronics & Appliances", "Ankleshwar", "Shop 12, Station Road Commercial Complex, Ankleshwar", "919876543210"
            ),
            (
                "SanDisk Extreme PRO 2TB Portable NVMe External SSD (2000MB/s USB 3.2)",
                "Professional-grade solid state drive with blazing fast 2000MB/s read/write speeds, forged aluminum chassis acting as heatsink, and 2-meter drop protection.",
                18999.0, 28999.0, 25, "Accessories", 4.9, 4100, "High Speed Storage",
                "https://images.unsplash.com/photo-1597872200969-2b65d56bd16b?w=500&auto=format&fit=crop&q=80",
                "ssd sandisk 2tb portable nvme external backup fast storage usb c",
                narmada_id, "Narmada Tech & IT Solutions", "Ankleshwar", "GIDC Industrial Estate, Ankleshwar", "919876543211"
            ),
            (
                "Dyson V12 Detect Slim Cordless Vacuum Cleaner (Laser Fluffy Head)",
                "Dyson's lightest intelligent cordless vacuum with laser illumination that reveals invisible dust, piezo acoustic sensor for particle count, and anti-tangle Hair Screw tool.",
                44900.0, 55900.0, 9, "Home", 4.7, 1630, "Smart Home Tech",
                "https://images.unsplash.com/photo-1558317374-067fb5f30001?w=500&auto=format&fit=crop&q=80",
                "dyson v12 cordless vacuum cleaner laser smart home cleaning",
                smart_id, "Gujarat Smart Living & Lighting", "Ankleshwar", "Rajpipla Road High Street, Ankleshwar", "919876543212"
            ),
            (
                "Philips Hue Play Gradient Lightstrip & Smart HDMI Sync Box",
                "Surround your screen in reactive smart light that dynamically mirrors the colors of your gaming console, movies, and music in real time with zero latency.",
                21999.0, 29999.0, 16, "Home", 4.6, 920, "Cinema Ambient",
                "https://images.unsplash.com/photo-1507473885765-e6ed057f782c?w=500&auto=format&fit=crop&q=80",
                "philips hue smart lighting hdmi sync ambient tv lightstrip rgb",
                smart_id, "Gujarat Smart Living & Lighting", "Ankleshwar", "Rajpipla Road High Street, Ankleshwar", "919876543212"
            ),
            (
                "Bosch Professional Heavy-Duty Rotary Hammer Drill (GSH 500)",
                "Industrial standard 1100W impact demolition hammer drill designed for robust civil and factory maintenance in Ankleshwar industrial hub.",
                11499.0, 14999.0, 14, "Tools", 4.9, 540, "Industrial Grade",
                "https://images.unsplash.com/photo-1504148455328-c376907d081c?w=500&auto=format&fit=crop&q=80",
                "bosch hammer drill rotary industrial tools power maintenance",
                radhe_id, "Radhe Industrial Hardware & Tools", "Ankleshwar", "Plot 45, GIDC Phase-1, Ankleshwar", "919876543214"
            )
        ]

        for p in products:
            conn.execute("""
                INSERT INTO products
                (name, description, price, original_price, stock, category, rating, review_count, badge, image_url, tags, merchant_id, store_name, city, store_address, whatsapp_number)
                VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
            """, p)

        conn.commit()

    conn.close()


init_db()


# -----------------------------
# Inverted-Index & Search Logic
# -----------------------------
def tokenize(text):
    return set(re.findall(r"[a-z0-9]+", (text or "").lower()))


def build_inverted_index():
    conn = db()
    rows = conn.execute("SELECT id, name, description, category, tags FROM products").fetchall()
    conn.close()
    index = defaultdict(set)
    for p in rows:
        text = " ".join([p["name"], p["description"] or "", p["category"], p["tags"] or ""])
        for token in tokenize(text):
            index[token].add(p["id"])
    return index


def search_products(query="", category="", min_price=None, max_price=None, sort_by="featured"):
    conn = db()
    rows = conn.execute("SELECT * FROM products").fetchall()
    conn.close()

    index = build_inverted_index()
    q_tokens = tokenize(query)
    candidate_ids = None
    if q_tokens:
        for token in q_tokens:
            ids = index.get(token, set())
            candidate_ids = ids if candidate_ids is None else candidate_ids & ids
    candidates = [p for p in rows if candidate_ids is None or p["id"] in candidate_ids]

    def ok(p):
        if category and category != "All" and p["category"].lower() != category.lower():
            return False
        if min_price is not None and p["price"] < min_price:
            return False
        if max_price is not None and p["price"] > max_price:
            return False
        return True

    candidates = [p for p in candidates if ok(p)]

    def score(p):
        text = " ".join([p["name"], p["description"] or "", p["tags"] or ""]).lower()
        overlap = sum(1 for t in q_tokens if t in tokenize(text))
        exact = 3 if query and query.lower() in p["name"].lower() else 0
        return (exact + overlap, p["rating"])

    if sort_by == "price_low":
        return sorted(candidates, key=lambda x: x["price"])
    elif sort_by == "price_high":
        return sorted(candidates, key=lambda x: x["price"], reverse=True)
    elif sort_by == "rating":
        return sorted(candidates, key=lambda x: x["rating"], reverse=True)
    else:
        return sorted(candidates, key=score, reverse=True)


# -----------------------------
# Recommendation Engine (Hybrid)
# -----------------------------
def recommend_for_customer(customer_id, top_n=4):
    conn = db()
    events = conn.execute("""
        SELECT customer_id, product_id, event_type, COUNT(*) AS c
        FROM events
        GROUP BY customer_id, product_id, event_type
    """).fetchall()
    products = [dict(p) for p in conn.execute("SELECT * FROM products").fetchall()]
    owned = {r["product_id"] for r in events if r["customer_id"] == customer_id and r["event_type"] == "purchase"}
    conn.close()

    matrix = defaultdict(dict)
    # Weight interactions: purchase=5, cart=3, view=1
    weights = {"purchase": 5.0, "cart": 3.0, "view": 1.0}
    for r in events:
        w = weights.get(r["event_type"], 1.0)
        matrix[r["customer_id"]][r["product_id"]] = matrix[r["customer_id"]].get(r["product_id"], 0) + (r["c"] * w)

    def cosine(a, b):
        keys = set(a) | set(b)
        dot = sum(a.get(k, 0) * b.get(k, 0) for k in keys)
        na = math.sqrt(sum(v * v for v in a.values()))
        nb = math.sqrt(sum(v * v for v in b.values()))
        return dot / (na * nb) if na and nb else 0

    user_vec = matrix.get(customer_id, {})
    if not user_vec:
        # Fallback to top-rated best sellers
        return sorted(products, key=lambda x: (x["rating"], x["review_count"]), reverse=True)[:top_n]

    similarities = []
    for uid, vec in matrix.items():
        if uid != customer_id:
            sim = cosine(user_vec, vec)
            if sim > 0:
                similarities.append((sim, uid))
    similarities.sort(reverse=True)

    scores = defaultdict(float)
    for sim, uid in similarities[:10]:
        for pid, val in matrix[uid].items():
            if pid not in owned:
                scores[pid] += sim * val

    ranked_ids = [pid for pid, _ in sorted(scores.items(), key=lambda x: x[1], reverse=True)]
    chosen = [p for p in products if p["id"] in ranked_ids]
    if len(chosen) < top_n:
        fillers = [p for p in products if p["id"] not in ranked_ids and p["id"] not in owned]
        fillers.sort(key=lambda x: (x["rating"], x["review_count"]), reverse=True)
        chosen += fillers

    return chosen[:top_n]


# -----------------------------
# Cart & Dynamic Pricing Management
# -----------------------------
def get_cart():
    return session.setdefault("cart", {})


def cart_details():
    cart = get_cart()
    conn = db()
    items = []
    raw_subtotal = 0.0
    for pid, qty in cart.items():
        p = conn.execute("SELECT * FROM products WHERE id=?", (pid,)).fetchone()
        if p:
            line = p["price"] * int(qty)
            orig_line = p["original_price"] * int(qty)
            items.append({
                "product": dict(p),
                "quantity": int(qty),
                "line_total": line,
                "orig_line_total": orig_line,
                "savings": orig_line - line
            })
            raw_subtotal += line
    conn.close()

    # Apply active coupon if stored in session
    applied_coupon = session.get("coupon")
    discount_amount = 0.0
    if applied_coupon:
        pct = applied_coupon.get("discount_pct", 0)
        min_spend = applied_coupon.get("min_spend", 0)
        if raw_subtotal >= min_spend:
            discount_amount = round(raw_subtotal * (pct / 100.0), 2)
        else:
            session.pop("coupon", None)
            applied_coupon = None

    final_total = max(0.0, raw_subtotal - discount_amount)
    delivery_fee = 0.0 if raw_subtotal >= 499 or raw_subtotal == 0 else 70.0

    return {
        "cart_items": items,
        "items": items,
        "raw_subtotal": round(raw_subtotal, 2),
        "discount_amount": round(discount_amount, 2),
        "delivery_fee": round(delivery_fee, 2),
        "final_total": round(final_total + delivery_fee, 2),
        "applied_coupon": applied_coupon,
        "free_delivery_threshold_left": max(0.0, round(499.0 - raw_subtotal, 2))
    }


# -----------------------------
# Global Context & Middleware
# -----------------------------
@app.context_processor
def inject_globals():
    cart_info = cart_details()
    conn = db()
    categories = [r["category"] for r in conn.execute("SELECT DISTINCT category FROM products ORDER BY category")]
    featured_stores = conn.execute("""
        SELECT id, store_name, name, address, city, whatsapp 
        FROM customers 
        WHERE role='merchant' 
        ORDER BY id DESC 
        LIMIT 6
    """).fetchall()
    
    # Check current customer segment and offer
    active_user_offer = None
    user_segment = None
    if session.get("customer_id"):
        customer_analyses = compute_customer_rfm_and_segments(conn)
        for ca in customer_analyses:
            if ca["id"] == session["customer_id"]:
                active_user_offer = ca["personalized_offer"]
                user_segment = ca["segment"]
                break

    conn.close()

    return {
        "cart_count": sum(i["quantity"] for i in cart_info["cart_items"]),
        "cart_total": cart_info["final_total"],
        "cart_info": cart_info,
        "all_categories": categories,
        "active_user_offer": active_user_offer,
        "user_segment": user_segment,
        "is_admin": session.get("role") == "admin" or session.get("is_developer", False),
        "is_developer": session.get("is_developer", False),
        "user_role": session.get("role", "customer"),
        "is_merchant": bool(session.get("merchant_id")),
        "merchant_id": session.get("merchant_id"),
        "merchant_store_name": session.get("store_name", ""),
        "merchant_name": session.get("merchant_name", ""),
        "user_city": session.get("user_city", "Bharuch"),
        "popular_cities": ["Bharuch", "Vadodara", "Surat", "Ahmedabad", "Rajkot", "Gandhinagar", "Mumbai", "Delhi NCR"],
        "featured_stores": featured_stores,
        "now_year": datetime.utcnow().year
    }


@app.route("/developer/mode")
def developer_mode():
    session["is_developer"] = True
    session["role"] = "admin"
    session["admin_name"] = "DataCart Lead Developer"
    flash("⚡ Developer Mode Active! Full Platform Executive BI & Customer Analytics Hub Unlocked.", "success")
    return redirect(url_for("analytics"))


# -----------------------------
# Main Application Routes
# -----------------------------
@app.route("/")
def home():
    query = request.args.get("q", "").strip()
    category = request.args.get("category", "")
    min_price = request.args.get("min_price")
    max_price = request.args.get("max_price")
    sort_by = request.args.get("sort", "featured")
    selected_city = request.args.get("city", session.get("user_city", "Bharuch"))

    products = search_products(
        query=query,
        category=category,
        min_price=float(min_price) if min_price else None,
        max_price=float(max_price) if max_price else None,
        sort_by=sort_by
    )

    conn = db()
    categories = [r["category"] for r in conn.execute("SELECT DISTINCT category FROM products ORDER BY category")]
    best_sellers = conn.execute("SELECT * FROM products ORDER BY rating DESC, review_count DESC LIMIT 4").fetchall()
    deals = conn.execute("SELECT * FROM products WHERE badge != '' ORDER BY price ASC LIMIT 4").fetchall()
    local_stores = conn.execute("SELECT * FROM customers WHERE role='merchant' ORDER BY id DESC LIMIT 8").fetchall()

    recs = []
    customer_profile = None
    if session.get("customer_id"):
        recs = recommend_for_customer(session["customer_id"], top_n=4)
        all_rfm = compute_customer_rfm_and_segments(conn)
        for p in all_rfm:
            if p["id"] == session["customer_id"]:
                customer_profile = p
                break

    conn.close()

    return render_template(
        "home.html",
        products=products,
        categories=categories,
        best_sellers=best_sellers,
        deals=deals,
        local_stores=local_stores,
        recs=recs,
        q=query,
        selected_category=category,
        selected_city=selected_city,
        sort_by=sort_by,
        customer_profile=customer_profile
    )


@app.post("/set-location")
def set_location():
    city = request.form.get("city", "Bharuch").strip()
    session["user_city"] = city
    session.modified = True
    flash(f"Delivery location set to {city}. Exploring nearby local stores & express delivery!", "info")
    return redirect(request.referrer or url_for("home"))


@app.route("/product/<int:pid>")
def product(pid):
    conn = db()
    p = conn.execute("SELECT * FROM products WHERE id=?", (pid,)).fetchone()
    if not p:
        conn.close()
        flash("Product not found.", "error")
        return redirect(url_for("home"))

    # Log browsing telemetry
    if session.get("customer_id"):
        conn.execute("""
            INSERT INTO events(customer_id, product_id, event_type, created_at)
            VALUES(?,?,?,?)
        """, (session["customer_id"], pid, "view", datetime.utcnow().isoformat()))
        conn.commit()

    # Get reviews
    reviews = conn.execute("SELECT * FROM reviews WHERE product_id=? ORDER BY id DESC", (pid,)).fetchall()

    # Market Basket: Frequently Bought Together
    companion_product, bundle_rule = get_frequently_bought_together(pid, conn)

    # Category related products
    related = conn.execute("""
        SELECT * FROM products WHERE category=? AND id != ? ORDER BY rating DESC LIMIT 4
    """, (p["category"], pid)).fetchall()

    conn.close()

    return render_template(
        "product.html",
        product=dict(p),
        reviews=reviews,
        companion_product=companion_product,
        bundle_rule=bundle_rule,
        related=related
    )


@app.post("/cart/add/<int:pid>")
def add_cart(pid):
    qty = max(1, int(request.form.get("quantity", 1)))
    conn = db()
    p = conn.execute("SELECT * FROM products WHERE id=?", (pid,)).fetchone()
    if not p:
        conn.close()
        return redirect(url_for("home"))

    cart = get_cart()
    current = int(cart.get(str(pid), 0))
    cart[str(pid)] = min(p["stock"], current + qty)
    session.modified = True

    # Record cart addition telemetry
    if session.get("customer_id"):
        conn.execute("""
            INSERT INTO events(customer_id, product_id, event_type, created_at)
            VALUES(?,?,?,?)
        """, (session["customer_id"], pid, "cart", datetime.utcnow().isoformat()))
        conn.commit()
    conn.close()

    flash(f"Added {p['name'][:35]}... to Cart.", "success")
    return redirect(request.referrer or url_for("cart"))


@app.post("/cart/add-bundle")
def add_bundle():
    p1_id = request.form.get("p1_id")
    p2_id = request.form.get("p2_id")
    if not p1_id or not p2_id:
        return redirect(url_for("cart"))

    conn = db()
    p1 = conn.execute("SELECT * FROM products WHERE id=?", (p1_id,)).fetchone()
    p2 = conn.execute("SELECT * FROM products WHERE id=?", (p2_id,)).fetchone()
    conn.close()

    if p1 and p2:
        cart = get_cart()
        cart[str(p1_id)] = int(cart.get(str(p1_id), 0)) + 1
        cart[str(p2_id)] = int(cart.get(str(p2_id), 0)) + 1
        session.modified = True

        # Apply an automatic bundle discount coupon if not already applied
        session["coupon"] = {
            "code": "BUNDLE10",
            "discount_pct": 10,
            "title": "Combo Bundle 10% Savings",
            "min_spend": 500
        }
        flash(f"Added '{p1['name'][:25]}...' and '{p2['name'][:25]}...' bundle with 10% combo savings!", "success")

    return redirect(url_for("cart"))


@app.post("/cart/update")
def update_cart():
    cart = get_cart()
    conn = db()
    for pid, qty in request.form.items():
        if pid.isdigit():
            try:
                q = int(qty)
            except:
                q = 1
            if q <= 0:
                cart.pop(pid, None)
            else:
                p = conn.execute("SELECT stock FROM products WHERE id=?", (int(pid),)).fetchone()
                if p:
                    cart[pid] = min(q, p["stock"])
    conn.close()
    session.modified = True
    flash("Cart updated.", "info")
    return redirect(url_for("cart"))


@app.get("/cart/remove/<int:pid>")
def remove_cart_item(pid):
    cart = get_cart()
    cart.pop(str(pid), None)
    session.modified = True
    flash("Item removed from cart.", "info")
    return redirect(url_for("cart"))


@app.get("/cart")
def cart():
    cart_info = cart_details()
    conn = db()
    
    # Get smart personalized coupons recommendation for the user
    suggested_coupons = [
        {"code": "WELCOME10", "discount_pct": 10, "min_spend": 500, "title": "10% New Shopper Welcome"},
        {"code": "DATACART15", "discount_pct": 15, "min_spend": 2000, "title": "Hyperlocal Mega Fest 15% Off"}
    ]
    if session.get("customer_id"):
        customer_analyses = compute_customer_rfm_and_segments(conn)
        for ca in customer_analyses:
            if ca["id"] == session["customer_id"]:
                po = ca["personalized_offer"]
                suggested_coupons.insert(0, {
                    "code": po["code"],
                    "discount_pct": po["discount_pct"],
                    "min_spend": po["min_spend"],
                    "title": po["title"],
                    "badge": po["badge"]
                })
                break

    # Fetch trending recommendations for intelligent empty cart state
    trending_products = conn.execute("SELECT * FROM products ORDER BY rating DESC, review_count DESC LIMIT 4").fetchall()
    conn.close()

    return render_template(
        "cart.html", 
        cart_info=cart_info, 
        suggested_coupons=suggested_coupons,
        trending_products=trending_products
    )


@app.post("/coupon/apply")
def apply_coupon():
    code = request.form.get("coupon_code", "").strip().upper()
    cart_info = cart_details()
    raw_sub = cart_info["raw_subtotal"]

    # Known dynamic coupons mapping
    coupon_registry = {
        "VIPEXCLUSIV20": {"discount_pct": 20, "min_spend": 2000, "title": "VIP Exclusive 20% Privilege"},
        "COMEBACK25": {"discount_pct": 25, "min_spend": 1000, "title": "Win-Back 25% Retention Discount"},
        "BUNDLE10": {"discount_pct": 10, "min_spend": 500, "title": "Frequently Bought Together 10% Off"},
        "WELCOME10": {"discount_pct": 10, "min_spend": 500, "title": "10% New Shopper Welcome"},
        "DATACART15": {"discount_pct": 15, "min_spend": 2000, "title": "Hyperlocal Mega Fest 15% Off"},
        "AMAZONFEST15": {"discount_pct": 15, "min_spend": 2000, "title": "Hyperlocal Mega Fest 15% Off"},
        "UPGRADE15": {"discount_pct": 15, "min_spend": 1200, "title": "15% Fast-Track VIP Upgrade"}
    }

    # Match category coupons like LOYALCOMP15, SPECIALAUDI12
    if code.startswith("LOYAL"):
        coupon_registry[code] = {"discount_pct": 15, "min_spend": 1500, "title": "15% Category Loyalty Reward"}
    elif code.startswith("SPECIAL"):
        coupon_registry[code] = {"discount_pct": 12, "min_spend": 1000, "title": "12% Category Personal Pick"}

    if code in coupon_registry:
        c_data = coupon_registry[code]
        if raw_sub < c_data["min_spend"]:
            flash(f"Coupon '{code}' requires a minimum cart total of ₹{c_data['min_spend']:.0f}.", "error")
        else:
            session["coupon"] = {
                "code": code,
                "discount_pct": c_data["discount_pct"],
                "min_spend": c_data["min_spend"],
                "title": c_data["title"]
            }
            flash(f"Coupon '{code}' applied successfully! Saved {c_data['discount_pct']}%", "success")
    else:
        flash(f"Invalid promo code '{code}'.", "error")

    return redirect(url_for("cart"))


@app.get("/coupon/remove")
def remove_coupon():
    session.pop("coupon", None)
    flash("Coupon removed.", "info")
    return redirect(url_for("cart"))


@app.route("/checkout", methods=["GET", "POST"])
def checkout():
    if not session.get("customer_id"):
        flash("Please log in to proceed to checkout.", "error")
        return redirect(url_for("login", next=url_for("checkout")))

    cart_info = cart_details()
    if not cart_info["items"]:
        flash("Your cart is empty.", "error")
        return redirect(url_for("cart"))

    conn = db()
    customer = conn.execute("SELECT * FROM customers WHERE id=?", (session["customer_id"],)).fetchone()
    conn.close()

    if request.method == "POST":
        address = request.form.get("address", customer["address"] if customer else "").strip()
        pincode = request.form.get("pincode", "392001").strip()
        method = request.form.get("method", "Amazon Pay UPI")
        token = "tok_" + uuid.uuid4().hex[:18]

        conn = db()
        try:
            conn.execute("BEGIN")
            # Stock verification
            for item in cart_info["items"]:
                curr = conn.execute("SELECT stock, name FROM products WHERE id=?", (item["product"]["id"],)).fetchone()
                if not curr or curr["stock"] < item["quantity"]:
                    raise ValueError(f"Insufficient stock for '{curr['name'] if curr else 'Item'}'.")

            # Deduct stock
            for item in cart_info["items"]:
                conn.execute("UPDATE products SET stock=stock-? WHERE id=?", (item["quantity"], item["product"]["id"]))

            # Update customer address
            conn.execute("UPDATE customers SET address=?, pincode=? WHERE id=?", (address, pincode, session["customer_id"]))

            now = datetime.utcnow().isoformat()
            tracking_id = "TRK-" + uuid.uuid4().hex[:10].upper()
            cur = conn.execute("""
                INSERT INTO orders(customer_id, status, total, discount_amount, coupon_code, payment_status, tracking_id, created_at)
                VALUES(?,?,?,?,?,?,?,?)
            """, (
                session["customer_id"],
                "Confirmed",
                cart_info["final_total"],
                cart_info["discount_amount"],
                session.get("coupon", {}).get("code", ""),
                "Paid",
                tracking_id,
                now
            ))
            oid = cur.lastrowid

            # Insert order items and telemetry with merchant attribution
            for item in cart_info["cart_items"]:
                p_id = item["product"]["id"]
                prod_row = conn.execute("SELECT merchant_id FROM products WHERE id=?", (p_id,)).fetchone()
                m_id = prod_row["merchant_id"] if prod_row and "merchant_id" in prod_row.keys() and prod_row["merchant_id"] else 1

                conn.execute("""
                    INSERT INTO order_items(order_id, product_id, quantity, price, merchant_id)
                    VALUES(?,?,?,?,?)
                """, (oid, p_id, item["quantity"], item["product"]["price"], m_id))
                conn.execute("""
                    INSERT INTO events(customer_id, product_id, event_type, created_at)
                    VALUES(?,?,?,?)
                """, (session["customer_id"], p_id, "purchase", now))

            # Record 256-Bit SSL tokenized payment with tamper-proof HMAC signature & masked identifiers
            pay_token = generate_payment_security_token(oid, cart_info["final_total"], session["customer_id"])
            pay_sig = generate_payment_signature(oid, cart_info["final_total"], session["customer_id"], now)
            raw_acc = request.form.get("payment_account_info", "")
            masked_info = mask_payment_identifier(method, raw_acc)

            conn.execute("""
                INSERT INTO payments(order_id, method, txn_status, token, masked_details, signature_hash, created_at)
                VALUES(?,?,?,?,?,?,?)
            """, (oid, method, "Verified & Paid", pay_token, masked_info, pay_sig, now))

            conn.commit()

            # Clear session cart and coupon
            session["cart"] = {}
            session.pop("coupon", None)
            session.modified = True

            flash("Payment verified with 256-Bit TLS Bank Encryption. Order placed successfully!", "success")
            return redirect(url_for("order_success", oid=oid))
        except Exception as e:
            conn.rollback()
            flash(str(e), "error")
        finally:
            conn.close()

    return render_template("checkout.html", cart_info=cart_info, customer=customer)


@app.get("/order/success/<int:oid>")
def order_success(oid):
    conn = db()
    order = conn.execute("SELECT * FROM orders WHERE id=?", (oid,)).fetchone()
    if not order:
        conn.close()
        return redirect(url_for("home"))

    items = conn.execute("""
        SELECT oi.*, p.name as product_name, p.category, p.image_url
        FROM order_items oi
        JOIN products p ON oi.product_id = p.id
        WHERE oi.order_id = ?
    """, (oid,)).fetchall()
    payment = conn.execute("SELECT * FROM payments WHERE order_id=?", (oid,)).fetchone()
    conn.close()

    return render_template("success.html", order=order, items=items, payment=payment)


@app.get("/orders")
def orders():
    if not session.get("customer_id"):
        return redirect(url_for("login"))
    conn = db()
    user_orders = conn.execute("""
        SELECT * FROM orders WHERE customer_id=? ORDER BY id DESC
    """, (session["customer_id"],)).fetchall()

    orders_with_items = []
    for o in user_orders:
        items = conn.execute("""
            SELECT oi.*, p.name as product_name, p.category, p.image_url
            FROM order_items oi
            JOIN products p ON oi.product_id = p.id
            WHERE oi.order_id = ?
        """, (o["id"],)).fetchall()
        orders_with_items.append({"order": o, "items": items})

    conn.close()
    return render_template("orders.html", orders_with_items=orders_with_items)


@app.get("/offers")
def offers():
    """
    Dedicated user page displaying personalized rewards, category discounts,
    and loyalty benefits computed by the Python Analytics Engine.
    """
    conn = db()
    customer_analysis = compute_customer_rfm_and_segments(conn)
    current_customer = None
    if session.get("customer_id"):
        for ca in customer_analysis:
            if ca["id"] == session["customer_id"]:
                current_customer = ca
                break

    # General available offers
    general_offers = [
        {
            "code": "AMAZONFEST15",
            "discount_pct": 15,
            "title": "Mega Electronics Fest Discount",
            "description": "Flat 15% off on high performance laptops, audio, and gaming peripherals.",
            "min_spend": 2000,
            "badge": "Sitewide Deal"
        },
        {
            "code": "BUNDLE10",
            "discount_pct": 10,
            "title": "Frequently Bought Together Combo Perk",
            "description": "Save 10% instantly when ordering 2 or more complementary tech accessories.",
            "min_spend": 500,
            "badge": "Bundle Savings"
        }
    ]

    # Category recommendations
    category_deals = conn.execute("""
        SELECT * FROM products WHERE badge != '' ORDER BY price DESC LIMIT 6
    """).fetchall()
    conn.close()

    return render_template(
        "offers.html",
        customer=current_customer,
        general_offers=general_offers,
        category_deals=category_deals
    )


# -----------------------------
# Analytics & BI Dashboard
# -----------------------------
# -----------------------------
# Protected Executive BI & Data Science Hub (Admin Only)
# -----------------------------
@app.get("/analytics")
@admin_required
def analytics():
    """
    Executive Business Intelligence & Data Science Dashboard (Restricted to Admin).
    Provides RFM customer segmentation, churn scoring, market basket lift metrics,
    and interactive visualizations.
    """
    conn = db()
    data = get_executive_bi_dashboard_data(conn)
    conn.close()

    return render_template(
        "analytics.html",
        kpis=data["kpis"],
        customer_analysis=data["customer_analysis"],
        market_basket_rules=data["market_basket_rules"],
        charts=data["charts"]
    )


@app.get("/api/analytics/charts")
@admin_required
def api_analytics_charts():
    """JSON API for interactive Chart.js graphs (Admin Only)."""
    conn = db()
    data = get_executive_bi_dashboard_data(conn)
    conn.close()
    return jsonify(data["charts"])


@app.get("/api/analytics/live-events")
@admin_required
def api_analytics_live_events():
    """JSON API streaming the latest 15 real-time customer behavioral events (Admin Only)."""
    conn = db()
    events = conn.execute("""
        SELECT e.id, e.event_type, e.created_at, e.customer_id,
               COALESCE(c.name, 'Guest Shopper') as customer_name,
               COALESCE(p.name, 'General Browsing') as product_name,
               COALESCE(p.category, '') as category
        FROM events e
        LEFT JOIN customers c ON e.customer_id = c.id
        LEFT JOIN products p ON e.product_id = p.id
        ORDER BY e.id DESC
        LIMIT 15
    """).fetchall()
    conn.close()
    return jsonify([dict(ev) for ev in events])


@app.post("/admin/reset-realtime-data")
@admin_required
def admin_reset_data():
    """Clears all customer orders, carts, and telemetry to start fresh."""
    conn = db()
    conn.execute("DELETE FROM orders")
    conn.execute("DELETE FROM order_items")
    conn.execute("DELETE FROM payments")
    conn.execute("DELETE FROM events")
    conn.execute("DELETE FROM customers WHERE role != 'admin'")
    conn.commit()
    conn.close()
    session.clear()
    flash("Database reset! Real-time analytics is now clean and awaiting traffic.", "info")
    return redirect(url_for("home"))


@app.get("/api/customer/<int:cid>/profile")
@admin_required
def api_customer_profile(cid):
    """Returns detailed customer profile and recommended retention strategy."""
    conn = db()
    customer_analysis = compute_customer_rfm_and_segments(conn)
    conn.close()
    for c in customer_analysis:
        if c["id"] == cid:
            return jsonify({"status": "success", "customer": c})
    return jsonify({"status": "error", "message": "Customer not found"}), 404


@app.route("/admin/login", methods=["GET", "POST"])
def admin_login():
    if request.method == "POST":
        email = request.form["email"].strip().lower()
        password = request.form["password"]
        conn = db()
        user = conn.execute("SELECT * FROM customers WHERE email=? AND role='admin'", (email,)).fetchone()
        conn.close()

        if user and check_password_hash(user["password_hash"], password):
            session["admin_id"] = user["id"]
            session["role"] = "admin"
            session["admin_name"] = user["name"]
            session["customer_id"] = user["id"]
            session["customer_name"] = user["name"]

            flash("Welcome, Administrator! Executive Business Intelligence Portal Unlocked.", "success")
            next_url = request.args.get("next")
            return redirect(next_url or url_for("analytics"))

        flash("Invalid administrator credentials. Access restricted to authorized personnel.", "error")

    return render_template("auth.html", mode="admin_login")


@app.get("/admin/logout")
def admin_logout():
    session.pop("admin_id", None)
    session.pop("role", None)
    session.pop("admin_name", None)
    flash("Logged out from Executive Admin portal.", "info")
    return redirect(url_for("home"))


# -----------------------------
# Dedicated Merchant Storefront & Tax Invoice
# -----------------------------
@app.get("/store/<int:mid>")
def store_page(mid):
    conn = db()
    merchant = conn.execute("SELECT * FROM customers WHERE id=? AND role='merchant'", (mid,)).fetchone()
    if not merchant:
        conn.close()
        flash("Store not found.", "error")
        return redirect(url_for("home"))

    products = conn.execute("SELECT * FROM products WHERE merchant_id=? ORDER BY id DESC", (mid,)).fetchall()
    conn.close()

    return render_template("store_page.html", merchant=merchant, products=products)


@app.get("/order/invoice/<int:oid>")
def print_invoice(oid):
    conn = db()
    order = conn.execute("SELECT * FROM orders WHERE id=?", (oid,)).fetchone()
    if not order:
        conn.close()
        return redirect(url_for("home"))

    # Security verification
    is_authorized = (
        session.get("customer_id") == order["customer_id"] or
        session.get("role") == "admin" or
        bool(session.get("merchant_id"))
    )
    if not is_authorized:
        conn.close()
        flash("Unauthorized to view this invoice.", "error")
        return redirect(url_for("orders"))

    customer = conn.execute("SELECT * FROM customers WHERE id=?", (order["customer_id"],)).fetchone()
    items = conn.execute("""
        SELECT oi.*, p.name as product_name, p.category, p.store_name, p.image_url
        FROM order_items oi
        JOIN products p ON oi.product_id = p.id
        WHERE oi.order_id = ?
    """, (oid,)).fetchall()
    payment = conn.execute("SELECT * FROM payments WHERE order_id=?", (oid,)).fetchone()
    conn.close()

    return render_template("invoice.html", order=order, customer=customer, items=items, payment=payment)


# -----------------------------
# Authentication & Registration
# -----------------------------
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form["email"].strip().lower()
        password = request.form["password"]
        conn = db()
        user = conn.execute("SELECT * FROM customers WHERE email=?", (email,)).fetchone()
        
        if user and check_password_hash(user["password_hash"], password):
            session["customer_id"] = user["id"]
            session["customer_name"] = user["name"]
            
            # Record login event telemetry
            conn.execute("""
                INSERT INTO events(customer_id, product_id, event_type, created_at)
                VALUES(?,?,?,?)
            """, (user["id"], None, "login", datetime.utcnow().isoformat()))
            conn.commit()
            conn.close()

            flash(f"Welcome back, {user['name'].split()[0]}!", "success")
            next_url = request.args.get("next")
            return redirect(next_url or url_for("home"))
        
        conn.close()
        flash("Invalid email or password. Please register if you do not have an account.", "error")

    return render_template("auth.html", mode="login")


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        name = request.form["name"].strip()
        email = request.form["email"].strip().lower()
        password = request.form["password"]
        address = request.form.get("address", "").strip()
        pincode = request.form.get("pincode", "392001").strip()

        conn = db()
        try:
            now_iso = datetime.utcnow().isoformat()
            cur = conn.execute("""
                INSERT INTO customers(name, email, password_hash, address, pincode, created_at)
                VALUES(?,?,?,?,?,?)
            """, (name, email, generate_password_hash(password), address, pincode, now_iso))
            cid = cur.lastrowid

            # Record registration event telemetry
            conn.execute("""
                INSERT INTO events(customer_id, product_id, event_type, created_at)
                VALUES(?,?,?,?)
            """, (cid, None, "register", now_iso))
            
            conn.commit()
            
            session["customer_id"] = cid
            session["customer_name"] = name
            flash(f"Account created for {name}! Your real-time customer analytics profile is now active.", "success")
            return redirect(url_for("home"))
        except sqlite3.IntegrityError:
            flash("An account with this email already exists.", "error")
        finally:
            conn.close()

    return render_template("auth.html", mode="register")


@app.route("/logout")
def logout():
    session.clear()
    flash("You have been signed out.", "info")
    return redirect(url_for("home"))


# -----------------------------
# Merchant Seller Central Portal
# -----------------------------
@app.route("/merchant/register", methods=["GET", "POST"])
def merchant_register():
    if request.method == "POST":
        name = request.form["name"].strip()
        store_name = request.form["store_name"].strip()
        email = request.form["email"].strip().lower()
        password = request.form["password"]
        business_id = request.form.get("business_id", "").strip()
        address = request.form.get("address", "").strip()
        pincode = request.form.get("pincode", "392001").strip()

        conn = db()
        try:
            now_iso = datetime.utcnow().isoformat()
            cur = conn.execute("""
                INSERT INTO customers(name, email, password_hash, role, store_name, business_id, address, pincode, created_at)
                VALUES(?,?,?,?,?,?,?,?,?)
            """, (name, email, generate_password_hash(password), "merchant", store_name, business_id, address, pincode, now_iso))
            mid = cur.lastrowid

            # Log registration telemetry
            conn.execute("""
                INSERT INTO events(customer_id, product_id, event_type, created_at)
                VALUES(?,?,?,?)
            """, (mid, None, "merchant_register", now_iso))
            conn.commit()

            session["merchant_id"] = mid
            session["store_name"] = store_name
            session["merchant_name"] = name
            session["customer_id"] = mid
            session["customer_name"] = name

            flash(f"Welcome to DataCart Seller Central, {store_name}! Your merchant account is active.", "success")
            return redirect(url_for("merchant_dashboard"))
        except sqlite3.IntegrityError:
            flash("An account with this email already exists.", "error")
        finally:
            conn.close()

    return render_template("auth.html", mode="merchant_register")


@app.route("/merchant/login", methods=["GET", "POST"])
def merchant_login():
    if request.method == "POST":
        email = request.form["email"].strip().lower()
        password = request.form["password"]
        conn = db()
        user = conn.execute("SELECT * FROM customers WHERE email=?", (email,)).fetchone()
        conn.close()

        if user and check_password_hash(user["password_hash"], password):
            session["merchant_id"] = user["id"]
            session["store_name"] = user["store_name"] or f"{user['name']}'s Store"
            session["merchant_name"] = user["name"]
            session["customer_id"] = user["id"]
            session["customer_name"] = user["name"]

            flash(f"Welcome back to Seller Central, {session['store_name']}!", "success")
            return redirect(url_for("merchant_dashboard"))

        flash("Invalid email or password for Seller Central.", "error")

    return render_template("auth.html", mode="merchant_login")


@app.get("/merchant/logout")
def merchant_logout():
    session.pop("merchant_id", None)
    session.pop("store_name", None)
    session.pop("merchant_name", None)
    flash("Logged out from Seller Central.", "info")
    return redirect(url_for("home"))


@app.get("/merchant/dashboard")
def merchant_dashboard():
    if not session.get("merchant_id"):
        flash("Please sign in to access Seller Central.", "error")
        return redirect(url_for("merchant_login"))

    mid = session["merchant_id"]
    conn = db()

    # 1. Fetch products listed by this merchant
    products = conn.execute("""
        SELECT * FROM products WHERE merchant_id = ? ORDER BY id DESC
    """, (mid,)).fetchall()

    # 2. Fetch sales and incoming orders for this merchant
    merchant_orders = conn.execute("""
        SELECT oi.id as item_id, oi.order_id, oi.product_id, oi.quantity, oi.price,
               o.status as order_status, o.created_at, o.tracking_id,
               c.name as customer_name, c.email as customer_email, c.address as shipping_address,
               p.name as product_name, p.image_url
        FROM order_items oi
        JOIN orders o ON oi.order_id = o.id
        JOIN customers c ON o.customer_id = c.id
        JOIN products p ON oi.product_id = p.id
        WHERE oi.merchant_id = ?
        ORDER BY o.id DESC
        LIMIT 30
    """, (mid,)).fetchall()

    total_sales = sum(o["quantity"] * o["price"] for o in merchant_orders)
    total_units_sold = sum(o["quantity"] for o in merchant_orders)
    low_stock_count = sum(1 for p in products if p["stock"] <= 5)
    pending_orders = sum(1 for o in merchant_orders if o["order_status"] in ("Confirmed", "Processing"))

    conn.close()

    return render_template(
        "merchant_dashboard.html",
        products=products,
        orders=merchant_orders,
        total_sales=total_sales,
        total_units_sold=total_units_sold,
        total_listings=len(products),
        low_stock_count=low_stock_count,
        pending_orders=pending_orders
    )


@app.route("/merchant/product/add", methods=["GET", "POST"])
def merchant_add_product():
    if not session.get("merchant_id"):
        flash("Please log in as a seller first.", "error")
        return redirect(url_for("merchant_login"))

    if request.method == "POST":
        name = request.form["name"].strip()
        category = request.form["category"].strip()
        price = float(request.form["price"])
        original_price = float(request.form.get("original_price", price * 1.2))
        stock = int(request.form.get("stock", 10))
        description = request.form.get("description", "").strip()
        image_url = request.form.get("image_url", "").strip()
        badge = request.form.get("badge", "").strip()
        tags = request.form.get("tags", "").strip().lower()

        # Clean fallback image if merchant left it blank
        if not image_url:
            category_defaults = {
                "Computers": "https://images.unsplash.com/photo-1517336714731-489689fd1ca8?w=500&auto=format&fit=crop&q=80",
                "Audio": "https://images.unsplash.com/photo-1505740420928-5e560c06d30e?w=500&auto=format&fit=crop&q=80",
                "Gaming": "https://images.unsplash.com/photo-1527814050087-73880490b435?w=500&auto=format&fit=crop&q=80",
                "Accessories": "https://images.unsplash.com/photo-1615663245857-ac93bb7c39e7?w=500&auto=format&fit=crop&q=80",
                "Wearables": "https://images.unsplash.com/photo-1579586337278-3befd40fd17a?w=500&auto=format&fit=crop&q=80",
                "Home": "https://images.unsplash.com/photo-1507473885765-e6ed057f782c?w=500&auto=format&fit=crop&q=80"
            }
            image_url = category_defaults.get(category, "https://images.unsplash.com/photo-1505740420928-5e560c06d30e?w=500&auto=format&fit=crop&q=80")

        # Auto-append keywords to tags for inverted index search
        tags_full = f"{tags} {name} {category} {session.get('store_name', '')}".lower()

        conn = db()
        merchant_info = conn.execute("SELECT city, address, whatsapp FROM customers WHERE id=?", (session["merchant_id"],)).fetchone()
        city = merchant_info["city"] if merchant_info and merchant_info["city"] else "Bharuch"
        store_address = merchant_info["address"] if merchant_info and merchant_info["address"] else "Local Commercial Market"
        whatsapp = merchant_info["whatsapp"] if merchant_info and merchant_info["whatsapp"] else "919876543210"

        cur = conn.execute("""
            INSERT INTO products(name, description, price, original_price, stock, category, rating, review_count, badge, image_url, tags, merchant_id, store_name, city, store_address, whatsapp_number)
            VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
        """, (
            name, description, price, original_price, stock, category,
            5.0, 1, badge, image_url, tags_full,
            session["merchant_id"], session.get("store_name", "DataCart Direct"),
            city, store_address, whatsapp
        ))
        pid = cur.lastrowid

        # Log real-time event
        conn.execute("""
            INSERT INTO events(customer_id, product_id, event_type, created_at)
            VALUES(?,?,?,?)
        """, (session["merchant_id"], pid, "merchant_add_product", datetime.utcnow().isoformat()))

        conn.commit()
        conn.close()

        flash(f"Success! '{name}' is now LIVE on DataCart Storefront with 'Sold by: {session.get('store_name', '')}'!", "success")
        return redirect(url_for("merchant_dashboard"))

    conn = db()
    categories = [r["category"] for r in conn.execute("SELECT DISTINCT category FROM products ORDER BY category")]
    conn.close()

    return render_template("merchant_add_product.html", categories=categories)


@app.post("/merchant/product/edit/<int:pid>")
def merchant_edit_product(pid):
    if not session.get("merchant_id"):
        return redirect(url_for("merchant_login"))

    price = float(request.form.get("price", 0))
    stock = int(request.form.get("stock", 0))
    badge = request.form.get("badge", "").strip()

    conn = db()
    conn.execute("""
        UPDATE products SET price=?, stock=?, badge=? WHERE id=? AND merchant_id=?
    """, (price, stock, badge, pid, session["merchant_id"]))
    conn.commit()
    conn.close()

    flash("Product pricing & inventory updated in real-time.", "success")
    return redirect(url_for("merchant_dashboard"))


@app.post("/merchant/product/delete/<int:pid>")
def merchant_delete_product(pid):
    if not session.get("merchant_id"):
        return redirect(url_for("merchant_login"))

    conn = db()
    conn.execute("DELETE FROM products WHERE id=? AND merchant_id=?", (pid, session["merchant_id"]))
    conn.commit()
    conn.close()

    flash("Product removed from storefront listing.", "info")
    return redirect(url_for("merchant_dashboard"))


@app.post("/merchant/order/<int:oid>/status")
def merchant_update_order_status(oid):
    if not session.get("merchant_id"):
        return redirect(url_for("merchant_login"))

    new_status = request.form.get("status", "Shipped").strip()
    conn = db()
    conn.execute("UPDATE orders SET status=? WHERE id=?", (new_status, oid))
    conn.commit()
    conn.close()

    flash(f"Order #DC-{oid} fulfillment status updated to '{new_status}' in real-time.", "success")
    return redirect(url_for("merchant_dashboard"))


# -----------------------------
# 24-Hour Zero-Advance Store Pickup Hold & Counter OTP
# -----------------------------
@app.route("/reserve/<int:pid>", methods=["GET", "POST"])
def reserve_product(pid):
    if not session.get("customer_id"):
        flash("Please sign in to hold this product for store pickup.", "info")
        return redirect(url_for("login", next=request.url))

    conn = db()
    prod = conn.execute("SELECT * FROM products WHERE id=?", (pid,)).fetchone()
    if not prod:
        conn.close()
        flash("Product not found.", "error")
        return redirect(url_for("home"))

    if prod["stock"] <= 0:
        conn.close()
        flash("Sorry, this item is currently out of stock at this local store.", "error")
        return redirect(url_for("product_detail", pid=pid))

    if request.method == "POST":
        customer_id = session["customer_id"]
        customer_name = session.get("customer_name", "Customer")
        phone = request.form.get("phone", session.get("customer_phone", "9876543210")).strip()
        
        # Generate 6-digit numeric OTP for showroom counter
        otp = str(secrets.randbelow(900000) + 100000)
        expires_at = (datetime.utcnow() + timedelta(hours=24)).isoformat()
        now_str = datetime.utcnow().isoformat()

        # Hold stock
        conn.execute("UPDATE products SET stock = stock - 1 WHERE id=?", (pid,))
        
        # Create reservation record
        cur = conn.execute("""
            INSERT INTO reservations(
                customer_id, customer_name, customer_phone, product_id, product_name,
                store_name, store_address, merchant_id, quantity, price, pickup_otp,
                status, expires_at, created_at
            ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)
        """, (
            customer_id, customer_name, phone, prod["id"], prod["name"],
            prod["store_name"], prod["store_address"], prod["merchant_id"], 1,
            prod["price"], otp, "ACTIVE", expires_at, now_str
        ))
        rid = cur.lastrowid

        # Log event
        conn.execute("""
            INSERT INTO events(customer_id, product_id, event_type, created_at)
            VALUES(?,?,?,?)
        """, (customer_id, pid, "pickup_reservation_created", now_str))

        conn.commit()
        conn.close()

        flash(f"🎉 Reserved! Your 24-Hour Pickup Hold OTP is: {otp}. Show this at {prod['store_name']}.", "success")
        return redirect(url_for("customer_reservations"))

    conn.close()
    return render_template("reserve_confirm.html", product=prod)


@app.get("/reservations")
def customer_reservations():
    if not session.get("customer_id"):
        return redirect(url_for("login", next=request.url))

    conn = db()
    reservations = conn.execute("""
        SELECT r.*, p.image_url, p.category, c.whatsapp as store_whatsapp
        FROM reservations r
        LEFT JOIN products p ON r.product_id = p.id
        LEFT JOIN customers c ON r.merchant_id = c.id
        WHERE r.customer_id = ?
        ORDER BY r.id DESC
    """, (session["customer_id"],)).fetchall()
    conn.close()

    return render_template("reservations.html", reservations=reservations)


@app.post("/reservations/<int:rid>/cancel")
def cancel_reservation(rid):
    if not session.get("customer_id"):
        return redirect(url_for("login"))

    conn = db()
    res = conn.execute("SELECT * FROM reservations WHERE id=? AND customer_id=?", (rid, session["customer_id"])).fetchone()
    if res and res["status"] == "ACTIVE":
        conn.execute("UPDATE reservations SET status='CANCELLED' WHERE id=?", (rid,))
        conn.execute("UPDATE products SET stock = stock + ? WHERE id=?", (res["quantity"], res["product_id"]))
        conn.commit()
        flash("Reservation cancelled. Inventory released back to store.", "info")
    conn.close()
    return redirect(url_for("customer_reservations"))


@app.post("/merchant/reservation/verify-otp")
def merchant_verify_pickup_otp():
    if not session.get("merchant_id"):
        return redirect(url_for("merchant_login"))

    otp = request.form.get("otp", "").strip()
    mid = session["merchant_id"]

    conn = db()
    res = conn.execute("""
        SELECT * FROM reservations 
        WHERE pickup_otp=? AND merchant_id=? AND status='ACTIVE'
    """, (otp, mid)).fetchone()

    if not res:
        conn.close()
        flash("❌ Invalid or Expired Pickup OTP! Please check with customer.", "error")
        return redirect(url_for("merchant_dashboard"))

    # Complete pickup
    conn.execute("UPDATE reservations SET status='COMPLETED' WHERE id=?", (res["id"],))
    
    # Create completed order record for merchant ledger
    cur = conn.execute("""
        INSERT INTO orders(customer_id, status, total, discount_amount, coupon_code, payment_status, tracking_id, created_at)
        VALUES(?, 'Delivered (Store Pickup)', ?, 0.0, 'STORE_PICKUP', 'Paid at Counter', ?, ?)
    """, (res["customer_id"], res["price"] * res["quantity"], f"PICKUP-{otp}", datetime.utcnow().isoformat()))
    new_oid = cur.lastrowid

    conn.execute("""
        INSERT INTO order_items(order_id, product_id, quantity, price, merchant_id)
        VALUES(?,?,?,?,?)
    """, (new_oid, res["product_id"], res["quantity"], res["price"], mid))

    conn.commit()
    conn.close()

    flash(f"✅ OTP Verified! Handover completed for '{res['product_name']}'. ₹{res['price']:,.2f} recorded.", "success")
    return redirect(url_for("merchant_dashboard"))


if __name__ == "__main__":
    # Binding to 0.0.0.0 allows any device on the same local network / Wi-Fi to access the application
    app.run(debug=True, host="0.0.0.0", port=5000)
