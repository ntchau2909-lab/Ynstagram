import os
import re
import sqlite3
from functools import wraps
from pathlib import Path

from flask import(
    Flask,
    flash,
    g,
    jsonify,
    redirect,
    render_template,
    request,
    session,
    url_for,
)
from werkzeug.security import(
    check_password_hash,
    generate_password_hash,
)

BASE_DIR = Path(__file__).resolve().parent
DATABASE_PATH = BASE_DIR / "database.db"

app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ.get(
    "SECRET_KEY",
    "development-secret-key-change-this",
)

app.config.update(
    SESSION_COOKIE_HTTPONLY = True,
    SESSION_COOKIE_SAMESITE = "Lax",
)

def get_database():
    """Mở kết nối SQLite trong request hiện tại."""
    if "databse" not in g:
        g.database = sqlite3.connect(DATABASE_PATH)
        g.database.row_factory = sqlite3.Row
    return g.database

@app.teardown_appcontext
def close_database(error = None):
    """Đóng kết nối SQLite sau request."""

    database = g.pop("database", None)
    
    if database is not None:
        database.close()

def login_required(view_function):
    """Chặn người chưa đăng nhập truy cập trang riêng tư."""

    @wraps(view_function)
    def wrapped_view(*args, **kwargs):
        if "user_id" not in session:
            flash(
                "Bạn cần đăng nhập để truy cập trang này.",
                "warning",
            )
            return redirect(url_for("login"))

        return view_function(*args, **kwargs)

    return wrapped_view

def is_valid_email(email):
    """Kiểm tra định dạng email cơ bản."""

    email_pattern = r"^[^\s@]+@[^\s@]+\.[^\s@]+$"
    return re.match(email_pattern, email) is not None

@app.route("/")
def home():
    return render_template("home.html")

@app.route("/register", methods=["GET", "POST"])
def register():
    if "user_id" in session:
        return redirect(url_for("dashboard"))

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        confirm_password = request.form.get(
            "confirm_password",
            "",
        )

        errors = []

        if not username:
            errors.append("Vui lòng nhập tên người dùng.")
        elif len(username) < 2:
            errors.append(
                "Tên người dùng phải có ít nhất 2 ký tự."
            )
        elif len(username) > 50:
            errors.append(
                "Tên người dùng không được vượt quá 50 ký tự."
            )

        if not email:
            errors.append("Vui lòng nhập địa chỉ email.")
        elif not is_valid_email(email):
            errors.append("Địa chỉ email không đúng định dạng.")
        elif len(email) > 254:
            errors.append(
                "Địa chỉ email không được vượt quá 254 ký tự."
            )

        if not password:
            errors.append("Vui lòng nhập mật khẩu.")
        elif len(password) < 8:
            errors.append(
                "Mật khẩu phải có ít nhất 8 ký tự."
            )
        elif len(password) > 128:
            errors.append(
                "Mật khẩu không được vượt quá 128 ký tự."
            )

        if not confirm_password:
            errors.append("Vui lòng nhập lại mật khẩu.")
        elif password != confirm_password:
            errors.append("Hai mật khẩu không giống nhau.")

        database = get_database()

        if email:
            existing_user = database.execute(
                """
                SELECT id
                FROM users
                WHERE email = ?
                """,
                (email,),
            ).fetchone()

            if existing_user is not None:
                errors.append(
                    "Địa chỉ email này đã được đăng ký."
                )

        if errors:
            for error in errors:
                flash(error, "error")

            return render_template(
                "register.html",
                entered_username=username,
                entered_email=email,
            )

        password_hash = generate_password_hash(password)

        try:
            database.execute(
                """
                INSERT INTO users (
                    username,
                    email,
                    password_hash
                )
                VALUES (?, ?, ?)
                """,
                (
                    username,
                    email,
                    password_hash,
                ),
            )

            database.commit()

        except sqlite3.IntegrityError:
            database.rollback()

            flash(
                "Không thể tạo tài khoản. Email có thể đã tồn tại.",
                "error",
            )

            return render_template(
                "register.html",
                entered_username=username,
                entered_email=email,
            )

        flash(
            "Đăng ký thành công! Hãy đăng nhập.",
            "success",
        )

        return redirect(url_for("login"))

    return render_template("register.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    if "user_id" in session:
        return redirect(url_for("dashboard"))

    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")

        errors = []

        if not email:
            errors.append("Vui lòng nhập địa chỉ email.")
        elif not is_valid_email(email):
            errors.append("Địa chỉ email không đúng định dạng.")

        if not password:
            errors.append("Vui lòng nhập mật khẩu.")

        if errors:
            for error in errors:
                flash(error, "error")

            return render_template(
                "login.html",
                entered_email=email,
            )

        database = get_database()

        user = database.execute(
            """
            SELECT
                id,
                username,
                email,
                password_hash
            FROM users
            WHERE email = ?
            """,
            (email,),
        ).fetchone()

        if user is None or not check_password_hash(
            user["password_hash"],
            password,
        ):
            flash(
                "Email hoặc mật khẩu không chính xác.",
                "error",
            )

            return render_template(
                "login.html",
                entered_email=email,
            )

        session.clear()

        session["user_id"] = user["id"]
        session["username"] = user["username"]
        session["email"] = user["email"]

        flash("Đăng nhập thành công!", "success")

        return redirect(url_for("dashboard"))

    return render_template("login.html")

@app.route("/logout", methods=["POST"])
@login_required
def logout():
    session.clear()

    flash("Bạn đã đăng xuất.", "success")

    return redirect(url_for("login"))

@app.errorhandler(404)
def page_not_found(error):
    return render_template("404.html"), 404
@app.route("/dashboard")
@login_required
def dashboard():
    return render_template("dashboard.html")

if __name__ == "__main__":
    app.run(debug=True)

