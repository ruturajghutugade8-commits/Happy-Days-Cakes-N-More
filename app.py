from decimal import Decimal
import os
import re
import secrets
from functools import wraps

import psycopg2
import razorpay
from psycopg2 import pool
from psycopg2.extras import RealDictCursor
from dotenv import load_dotenv
from flask import Flask, render_template, request, redirect, url_for, session, flash, abort
from werkzeug.security import generate_password_hash, check_password_hash

load_dotenv()

app = Flask(__name__)
app.config.update(
    SECRET_KEY=os.getenv("SECRET_KEY") or secrets.token_hex(32),
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=os.getenv("FLASK_ENV") == "production",
    MAX_CONTENT_LENGTH=2 * 1024 * 1024,
)

DB_CONFIG = {
    "host": os.getenv("DB_HOST"),
    "port": int(os.getenv("DB_PORT", 5432)),
    "user": os.getenv("DB_USER"),
    "password": os.getenv("DB_PASSWORD"),
    "dbname": os.getenv("DB_NAME", "postgres"),
    "connect_timeout": 10,
    "sslmode": os.getenv("DB_SSLMODE", "require"),
}

_db_pool = None


def get_razorpay_client():
    key_id = os.getenv("RAZORPAY_KEY_ID")
    key_secret = os.getenv("RAZORPAY_KEY_SECRET")
    if not key_id or not key_secret:
        return None
    return razorpay.Client(auth=(key_id, key_secret))


def get_pool():
    global _db_pool
    if _db_pool is None:
        _db_pool = psycopg2.pool.SimpleConnectionPool(
            1,
            int(os.getenv("DB_POOL_MAX", 5)),
            **DB_CONFIG,
        )
    return _db_pool


def query_db(query, params=(), fetch=False, fetchone=False):
    conn = get_pool().getconn()
    try:
        with conn.cursor(cursor_factory=RealDictCursor) as cursor:
            cursor.execute(query, params)
            if fetch:
                return cursor.fetchall()
            if fetchone:
                return cursor.fetchone()
            conn.commit()
            return None
    except Exception:
        conn.rollback()
        raise
    finally:
        get_pool().putconn(conn)


def transaction_queries(queries):
    conn = get_pool().getconn()
    try:
        with conn.cursor(cursor_factory=RealDictCursor) as cursor:
            result = None
            for query, params, wants_result in queries:
                cursor.execute(query, params)
                if wants_result:
                    result = cursor.fetchone()
            conn.commit()
            return result
    except Exception:
        conn.rollback()
        raise
    finally:
        get_pool().putconn(conn)


def admin_required():
    return "user_id" in session and session.get("is_admin") is True


def admin_only(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not admin_required():
            flash("Admin access required.")
            return redirect(url_for("login", next=request.path))
        return view(*args, **kwargs)
    return wrapped


def valid_email(email):
    return re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", email or "") is not None


def csrf_token():
    token = session.get("csrf_token")
    if not token:
        token = secrets.token_urlsafe(32)
        session["csrf_token"] = token
    return token


@app.context_processor
def inject_globals():
    return {
        "csrf_token": csrf_token,
        "cart_count": sum(session.get("cart", {}).values()),
        "online_payment_enabled": bool(os.getenv("RAZORPAY_KEY_ID") and os.getenv("RAZORPAY_KEY_SECRET")),
    }


@app.before_request
def protect_forms():
    if request.method == "POST":
        sent = request.form.get("csrf_token", "")
        expected = session.get("csrf_token", "")
        if not sent or not expected or not secrets.compare_digest(sent, expected):
            abort(400, description="Invalid form security token. Please refresh and try again.")


@app.after_request
def add_security_headers(response):
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "SAMEORIGIN")
    response.headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
    response.headers.setdefault("Permissions-Policy", "geolocation=(), microphone=(), camera=()")
    if request.path.startswith("/static/"):
        response.headers.setdefault("Cache-Control", "public, max-age=86400")
    return response


@app.route("/health")
def health():
    try:
        query_db("SELECT 1", fetchone=True)
        return {"status": "ok"}, 200
    except Exception:
        return {"status": "database_unavailable"}, 503


@app.route("/")
def home():
    category = request.args.get("category", "").strip()
    if category:
        products = query_db(
            "SELECT * FROM products WHERE is_available = TRUE AND category = %s ORDER BY id DESC",
            (category,), fetch=True
        )
    else:
        products = query_db(
            "SELECT * FROM products WHERE is_available = TRUE ORDER BY id DESC",
            fetch=True
        )
    categories = query_db(
        "SELECT DISTINCT category FROM products WHERE is_available = TRUE AND category IS NOT NULL AND category <> '' ORDER BY category",
        fetch=True,
    )
    return render_template("index.html", products=products, categories=categories, selected_category=category)


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        name = request.form.get("name", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")

        if len(name) < 2 or len(name) > 100 or not valid_email(email) or len(password) < 8:
            flash("Please enter valid details. Password must be at least 8 characters.", "error")
            return redirect(url_for("register"))

        if query_db("SELECT id FROM users WHERE email=%s", (email,), fetch=True):
            flash("Email already registered. Please login.", "error")
            return redirect(url_for("login"))

        query_db(
            "INSERT INTO users(name,email,password_hash) VALUES(%s,%s,%s)",
            (name, email, generate_password_hash(password, method="scrypt")),
        )
        flash("Account created successfully. Please login.", "success")
        return redirect(url_for("login"))

    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        user = query_db("SELECT * FROM users WHERE email=%s", (email,), fetchone=True)

        if user and check_password_hash(user["password_hash"], password):
            session.clear()
            session["csrf_token"] = secrets.token_urlsafe(32)
            session["user_id"] = user["id"]
            session["user_name"] = user["name"]
            session["is_admin"] = bool(user["is_admin"])
            flash("Welcome back!", "success")
            next_url = request.args.get("next")
            if next_url and next_url.startswith("/"):
                return redirect(next_url)
            return redirect(url_for("admin_dashboard") if session["is_admin"] else url_for("home"))

        flash("Invalid email or password.", "error")

    return render_template("login.html")


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("home"))


@app.route("/add-to-cart/<int:product_id>", methods=["POST"])
def add_to_cart(product_id):
    product = query_db(
        "SELECT id, name, price, is_available FROM products WHERE id=%s",
        (product_id,), fetchone=True
    )
    if not product or not product["is_available"]:
        flash("This item is currently unavailable.", "error")
        return redirect(url_for("home"))

    cart = session.get("cart", {})
    key = str(product_id)
    cart[key] = min(int(cart.get(key, 0)) + 1, 20)
    session["cart"] = cart
    flash(f"{product['name']} added to your cart.", "success")
    return redirect(request.referrer or url_for("home"))


@app.route("/cart")
def cart():
    cart_data = session.get("cart", {})
    if not cart_data:
        return render_template("cart.html", items=[], total=Decimal("0.00"))

    ids = [int(pid) for pid in cart_data.keys() if str(pid).isdigit()]
    products = query_db(
        "SELECT * FROM products WHERE id = ANY(%s) AND is_available = TRUE",
        (ids,), fetch=True
    ) if ids else []
    by_id = {str(p["id"]): p for p in products}

    items = []
    total = Decimal("0.00")
    clean_cart = {}
    for product_id, quantity in cart_data.items():
        product = by_id.get(str(product_id))
        if not product:
            continue
        quantity = max(1, min(int(quantity), 20))
        subtotal = Decimal(str(product["price"])) * quantity
        product["quantity"] = quantity
        product["subtotal"] = subtotal
        items.append(product)
        clean_cart[str(product_id)] = quantity
        total += subtotal
    session["cart"] = clean_cart
    return render_template("cart.html", items=items, total=total)


@app.route("/cart/update/<int:product_id>", methods=["POST"])
def update_cart(product_id):
    quantity = request.form.get("quantity", "1")
    try:
        quantity = int(quantity)
    except ValueError:
        quantity = 1
    cart = session.get("cart", {})
    if quantity <= 0:
        cart.pop(str(product_id), None)
    else:
        cart[str(product_id)] = min(quantity, 20)
    session["cart"] = cart
    return redirect(url_for("cart"))


@app.route("/remove-from-cart/<int:product_id>", methods=["POST"])
def remove_from_cart(product_id):
    cart = session.get("cart", {})
    cart.pop(str(product_id), None)
    session["cart"] = cart
    flash("Item removed from cart.", "success")
    return redirect(url_for("cart"))


@app.route("/checkout", methods=["GET", "POST"])
def checkout():
    if "user_id" not in session:
        flash("Please login before checkout.", "error")
        return redirect(url_for("login", next=url_for("checkout")))

    cart_data = session.get("cart", {})
    if not cart_data:
        flash("Your cart is empty.", "error")
        return redirect(url_for("cart"))

    ids = [int(pid) for pid in cart_data.keys() if str(pid).isdigit()]
    products = query_db(
        "SELECT * FROM products WHERE id = ANY(%s) AND is_available = TRUE",
        (ids,), fetch=True
    ) if ids else []
    by_id = {str(p["id"]): p for p in products}
    order_items = []
    total = Decimal("0.00")
    for product_id, quantity in cart_data.items():
        product = by_id.get(str(product_id))
        if not product:
            continue
        quantity = max(1, min(int(quantity), 20))
        subtotal = Decimal(str(product["price"])) * quantity
        order_items.append((product["id"], quantity, subtotal))
        total += subtotal

    if not order_items:
        session["cart"] = {}
        flash("Your cart is empty.", "error")
        return redirect(url_for("cart"))

    if request.method == "POST":
        phone = request.form.get("phone", "").strip()
        order_type = request.form.get("order_type", "pickup").strip().lower()
        address = request.form.get("delivery_address", "").strip()
        payment_method = request.form.get("payment_method", "pay_at_cafe").strip().lower()
        notes = request.form.get("notes", "").strip()

        if not re.fullmatch(r"[0-9+()\-\s]{10,20}", phone):
            flash("Please enter a valid phone number.", "error")
            return render_template("checkout.html", items=order_items, total=total)
        if order_type not in {"pickup", "delivery"}:
            order_type = "pickup"
        if order_type == "delivery" and len(address) < 8:
            flash("Please enter a delivery address.", "error")
            return render_template("checkout.html", items=order_items, total=total)
        if payment_method not in {"pay_at_cafe", "cash_on_delivery", "online"}:
            payment_method = "pay_at_cafe"
        razorpay_client = get_razorpay_client()
        if payment_method == "online" and not razorpay_client:
            flash("Online payment is not configured yet. Please choose Pay at Café.", "error")
            return render_template("checkout.html", items=order_items, total=total)

        payment_status = "Pending" if payment_method == "online" else "Unpaid"
        conn = get_pool().getconn()
        try:
            with conn.cursor(cursor_factory=RealDictCursor) as cursor:
                cursor.execute(
                    """
                    INSERT INTO orders(
                        user_id,total_amount,status,customer_phone,order_type,
                        delivery_address,payment_method,payment_status,notes
                    ) VALUES(%s,%s,'Placed',%s,%s,%s,%s,%s,%s)
                    RETURNING id
                    """,
                    (session["user_id"], total, phone, order_type, address or None,
                     payment_method, payment_status, notes or None),
                )
                order_id = cursor.fetchone()["id"]
                for product_id, quantity, subtotal in order_items:
                    cursor.execute(
                        "INSERT INTO order_items(order_id,product_id,quantity,subtotal) VALUES(%s,%s,%s,%s)",
                        (order_id, product_id, quantity, subtotal),
                    )
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            get_pool().putconn(conn)

        if payment_method == "online":
            try:
                razor_order = razorpay_client.order.create(data={
                    "amount": int(total * 100),
                    "currency": "INR",
                    "receipt": f"cafe-catta-{order_id}",
                })
                query_db(
                    "UPDATE orders SET razorpay_order_id=%s WHERE id=%s",
                    (razor_order["id"], order_id),
                )
                return render_template(
                    "payment.html",
                    order_id=order_id,
                    razorpay_order_id=razor_order["id"],
                    razorpay_key_id=os.getenv("RAZORPAY_KEY_ID"),
                    amount=int(total * 100),
                    customer_name=session.get("user_name", "Customer"),
                )
            except Exception:
                query_db(
                    "UPDATE orders SET status='Cancelled', payment_status='Failed' WHERE id=%s",
                    (order_id,),
                )
                flash("Online payment could not be started. Please try Pay at Café instead.", "error")
                return redirect(url_for("cart"))

        session["cart"] = {}
        flash(f"Order #{order_id} placed successfully.", "success")
        return redirect(url_for("orders"))

    return render_template("checkout.html", items=order_items, total=total)


@app.route("/payment/verify", methods=["POST"])
def verify_payment():
    razorpay_client = get_razorpay_client()
    if not razorpay_client or "user_id" not in session:
        return {"ok": False, "message": "Payment is not configured."}, 400

    order_id = request.form.get("order_id", "")
    payment_id = request.form.get("razorpay_payment_id", "")
    razor_order_id = request.form.get("razorpay_order_id", "")
    signature = request.form.get("razorpay_signature", "")

    local_order = query_db(
        "SELECT id, razorpay_order_id, total_amount FROM orders WHERE id=%s AND user_id=%s",
        (order_id, session["user_id"]), fetchone=True
    )
    if not local_order or local_order["razorpay_order_id"] != razor_order_id:
        flash("Payment verification failed.", "error")
        return redirect(url_for("cart"))

    try:
        razorpay_client.utility.verify_payment_signature({
            "razorpay_order_id": razor_order_id,
            "razorpay_payment_id": payment_id,
            "razorpay_signature": signature,
        })
    except Exception:
        query_db(
            "UPDATE orders SET status='Cancelled', payment_status='Failed' WHERE id=%s",
            (order_id,),
        )
        flash("Payment verification failed. The order was not confirmed.", "error")
        return redirect(url_for("cart"))

    query_db(
        "UPDATE orders SET payment_status='Paid', status='Placed', razorpay_payment_id=%s, razorpay_signature=%s WHERE id=%s",
        (payment_id, signature, order_id),
    )
    session["cart"] = {}
    flash(f"Payment successful. Order #{order_id} is confirmed.", "success")
    return redirect(url_for("orders"))


@app.route("/payment/failed")
def payment_failed():
    order_id = request.args.get("order_id")
    if order_id and "user_id" in session:
        query_db(
            "UPDATE orders SET status='Cancelled', payment_status='Failed' WHERE id=%s AND user_id=%s AND payment_status='Pending'",
            (order_id, session["user_id"]),
        )
    flash("Payment was cancelled. Your order has not been confirmed.", "error")
    return redirect(url_for("cart"))

@app.route("/gallery")
def gallery():
    return render_template("gallery.html")

@app.route("/orders")
def orders():
    if "user_id" not in session:
        return redirect(url_for("login", next=url_for("orders")))
    orders_list = query_db(
        "SELECT * FROM orders WHERE user_id=%s ORDER BY created_at DESC",
        (session["user_id"],), fetch=True
    )
    return render_template("orders.html", orders=orders_list)


# ================= ADMIN =================

@app.route("/admin")
@admin_only
def admin_dashboard():
    stats = {
        "users": query_db("SELECT COUNT(*) AS total FROM users", fetchone=True)["total"],
        "products": query_db("SELECT COUNT(*) AS total FROM products", fetchone=True)["total"],
        "orders": query_db("SELECT COUNT(*) AS total FROM orders", fetchone=True)["total"],
        "revenue": query_db(
            "SELECT COALESCE(SUM(total_amount),0) AS total FROM orders WHERE status <> 'Cancelled' AND payment_status <> 'Refunded'",
            fetchone=True,
        )["total"],
        "pending": query_db("SELECT COUNT(*) AS total FROM orders WHERE status IN ('Placed','Processing')", fetchone=True)["total"],
    }
    recent_orders = query_db(
        """
        SELECT o.id,u.name AS customer_name,o.total_amount,o.status,o.payment_status,o.created_at
        FROM orders o JOIN users u ON o.user_id=u.id
        ORDER BY o.created_at DESC LIMIT 10
        """, fetch=True
    )
    return render_template("admin_dashboard.html", stats=stats, recent_orders=recent_orders)


@app.route("/admin/users")
@admin_only
def admin_users():
    users = query_db(
        "SELECT id,name,email,is_admin,created_at FROM users ORDER BY created_at DESC",
        fetch=True,
    )
    return render_template("admin_users.html", users=users)


@app.route("/admin/users/delete/<int:user_id>", methods=["POST"])
@admin_only
def admin_delete_user(user_id):
    if user_id == session.get("user_id"):
        flash("You cannot delete your own admin account.", "error")
        return redirect(url_for("admin_users"))
    query_db("DELETE FROM users WHERE id=%s", (user_id,))
    flash("User deleted.", "success")
    return redirect(url_for("admin_users"))


@app.route("/admin/products")
@admin_only
def admin_products():
    products = query_db("SELECT * FROM products ORDER BY id DESC", fetch=True)
    return render_template("admin_products.html", products=products)


@app.route("/admin/products/add", methods=["GET", "POST"])
@admin_only
def add_product():
    if request.method == "POST":
        name = request.form.get("name", "").strip()
        description = request.form.get("description", "").strip()
        category = request.form.get("category", "Other").strip() or "Other"
        price = request.form.get("price", "")
        image = request.form.get("image", "").strip()
        is_available = request.form.get("is_available") == "on"
        try:
            price = Decimal(price)
            if not name or price <= 0 or len(name) > 150:
                raise ValueError
        except Exception:
            flash("Enter a valid product name and positive price.", "error")
            return redirect(url_for("add_product"))
        query_db(
            "INSERT INTO products(name,description,category,price,image,is_available) VALUES(%s,%s,%s,%s,%s,%s)",
            (name, description, category, price, image or None, is_available),
        )
        flash("Product added successfully.", "success")
        return redirect(url_for("admin_products"))
    return render_template("product_form.html", product=None)


@app.route("/admin/products/edit/<int:product_id>", methods=["GET", "POST"])
@admin_only
def edit_product(product_id):
    product = query_db("SELECT * FROM products WHERE id=%s", (product_id,), fetchone=True)
    if not product:
        flash("Product not found.", "error")
        return redirect(url_for("admin_products"))
    if request.method == "POST":
        name = request.form.get("name", "").strip()
        description = request.form.get("description", "").strip()
        category = request.form.get("category", "Other").strip() or "Other"
        price = request.form.get("price", "")
        image = request.form.get("image", "").strip()
        is_available = request.form.get("is_available") == "on"
        try:
            price = Decimal(price)
            if not name or price <= 0 or len(name) > 150:
                raise ValueError
        except Exception:
            flash("Enter valid product details.", "error")
            return redirect(url_for("edit_product", product_id=product_id))
        query_db(
            "UPDATE products SET name=%s,description=%s,category=%s,price=%s,image=%s,is_available=%s WHERE id=%s",
            (name, description, category, price, image or None, is_available, product_id),
        )
        flash("Product updated successfully.", "success")
        return redirect(url_for("admin_products"))
    return render_template("product_form.html", product=product)


@app.route("/admin/products/delete/<int:product_id>", methods=["POST"])
@admin_only
def delete_product(product_id):
    query_db("DELETE FROM products WHERE id=%s", (product_id,))
    flash("Product deleted.", "success")
    return redirect(url_for("admin_products"))


@app.route("/admin/orders")
@admin_only
def admin_orders():
    orders = query_db(
        """
        SELECT o.id,u.name AS customer_name,u.email AS customer_email,o.total_amount,
               o.status,o.payment_method,o.payment_status,o.order_type,o.created_at
        FROM orders o JOIN users u ON o.user_id=u.id
        ORDER BY o.created_at DESC
        """, fetch=True
    )
    return render_template("admin_orders.html", orders=orders)


@app.route("/admin/orders/<int:order_id>")
@admin_only
def admin_order_detail(order_id):
    order = query_db(
        """
        SELECT o.*,u.name AS customer_name,u.email AS customer_email
        FROM orders o JOIN users u ON o.user_id=u.id WHERE o.id=%s
        """, (order_id,), fetchone=True
    )
    if not order:
        flash("Order not found.", "error")
        return redirect(url_for("admin_orders"))
    items = query_db(
        """
        SELECT p.name AS product_name,oi.quantity,oi.subtotal
        FROM order_items oi JOIN products p ON oi.product_id=p.id
        WHERE oi.order_id=%s
        """, (order_id,), fetch=True
    )
    return render_template("admin_order_detail.html", order=order, items=items)


@app.route("/admin/orders/<int:order_id>/status", methods=["POST"])
@admin_only
def admin_update_order_status(order_id):
    status = request.form.get("status", "")
    payment_status = request.form.get("payment_status", "")
    allowed = {"Placed", "Processing", "Ready", "Shipped", "Delivered", "Cancelled"}
    payment_allowed = {"Unpaid", "Pending", "Paid", "Refunded"}
    if status not in allowed:
        flash("Invalid order status.", "error")
        return redirect(url_for("admin_order_detail", order_id=order_id))
    if payment_status not in payment_allowed:
        payment_status = "Unpaid"
    query_db(
        "UPDATE orders SET status=%s,payment_status=%s WHERE id=%s",
        (status, payment_status, order_id),
    )
    flash("Order status updated.", "success")
    return redirect(url_for("admin_order_detail", order_id=order_id))


@app.errorhandler(400)
def bad_request(error):
    return render_template("error.html", code=400, message=getattr(error, "description", "Bad request.")), 400


@app.errorhandler(404)
def not_found(error):
    return render_template("error.html", code=404, message="The page you requested could not be found."), 404


@app.errorhandler(500)
def server_error(error):
    return render_template("error.html", code=500, message="Something went wrong on the server. Please try again."), 500


if __name__ == "__main__":
    app.run(debug=os.getenv("FLASK_DEBUG", "false").lower() == "true")
