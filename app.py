import os
import re
import sqlite3
import uuid

from functools import wraps
from pathlib import Path

from flask import (
    Flask,
    flash,
    g,
    redirect,
    render_template,
    request,
    session,
    url_for,
)

from werkzeug.security import (
    check_password_hash,
    generate_password_hash,
)

from werkzeug.utils import secure_filename


# ========================================
# ĐƯỜNG DẪN CƠ BẢN
# ========================================

BASE_DIR = Path(__file__).resolve().parent

DATABASE_PATH = BASE_DIR / "database.db"

UPLOAD_FOLDER = BASE_DIR / "static" / "uploads"


# Tự động tạo thư mục uploads nếu chưa tồn tại
UPLOAD_FOLDER.mkdir(
    parents=True,
    exist_ok=True,
)


# ========================================
# CẤU HÌNH ỨNG DỤNG
# ========================================

app = Flask(__name__)

app.config["SECRET_KEY"] = os.environ.get(
    "SECRET_KEY",
    "development-secret-key-change-this",
)

app.config["UPLOAD_FOLDER"] = str(UPLOAD_FOLDER)

# Giới hạn dung lượng ảnh tối đa: 10 MB
app.config["MAX_CONTENT_LENGTH"] = 10 * 1024 * 1024

app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
)


# ========================================
# ĐỊNH DẠNG ẢNH ĐƯỢC PHÉP
# ========================================

ALLOWED_IMAGE_EXTENSIONS = {
    "png",
    "jpg",
    "jpeg",
    "gif",
    "webp",
}


# ========================================
# DATABASE
# ========================================

def get_database():
    """
    Mở kết nối SQLite trong request hiện tại.
    """

    if "database" not in g:
        g.database = sqlite3.connect(
            DATABASE_PATH
        )

        g.database.row_factory = sqlite3.Row

        # Bật hỗ trợ khóa ngoại
        g.database.execute(
            "PRAGMA foreign_keys = ON"
        )

    return g.database


@app.teardown_appcontext
def close_database(error=None):
    """
    Đóng kết nối SQLite sau mỗi request.
    """

    database = g.pop(
        "database",
        None,
    )

    if database is not None:
        database.close()


# ========================================
# KIỂM TRA ĐĂNG NHẬP
# ========================================

def login_required(view_function):
    """
    Chặn người chưa đăng nhập truy cập
    các trang riêng tư.
    """

    @wraps(view_function)
    def wrapped_view(*args, **kwargs):

        if "user_id" not in session:
            flash(
                "Bạn cần đăng nhập để truy cập trang này.",
                "warning",
            )

            return redirect(
                url_for("login")
            )

        return view_function(
            *args,
            **kwargs,
        )

    return wrapped_view


# ========================================
# HÀM KIỂM TRA DỮ LIỆU
# ========================================

def is_valid_email(email):
    """
    Kiểm tra định dạng email cơ bản.
    """

    email_pattern = (
        r"^[^\s@]+@[^\s@]+\.[^\s@]+$"
    )

    return (
        re.match(
            email_pattern,
            email,
        )
        is not None
    )


def allowed_image(filename):
    """
    Kiểm tra định dạng file ảnh.
    """

    if not filename:
        return False

    if "." not in filename:
        return False

    extension = filename.rsplit(
        ".",
        1,
    )[1].lower()

    return (
        extension
        in ALLOWED_IMAGE_EXTENSIONS
    )


# ========================================
# TRANG CHỦ
# ========================================

@app.route("/")
def home():

    if "user_id" in session:
        return redirect(
            url_for("dashboard")
        )

    return render_template(
        "home.html"
    )


# ========================================
# ĐĂNG KÝ
# ========================================

@app.route(
    "/register",
    methods=["GET", "POST"],
)
def register():

    if "user_id" in session:
        return redirect(
            url_for("dashboard")
        )

    if request.method == "POST":

        username = request.form.get(
            "username",
            "",
        ).strip()

        email = request.form.get(
            "email",
            "",
        ).strip().lower()

        password = request.form.get(
            "password",
            "",
        )

        confirm_password = request.form.get(
            "confirm_password",
            "",
        )

        errors = []

        # Kiểm tra tên người dùng
        if not username:
            errors.append(
                "Vui lòng nhập tên người dùng."
            )

        elif len(username) < 2:
            errors.append(
                "Tên người dùng phải có ít nhất 2 ký tự."
            )

        elif len(username) > 50:
            errors.append(
                "Tên người dùng không được vượt quá 50 ký tự."
            )

        # Kiểm tra email
        if not email:
            errors.append(
                "Vui lòng nhập địa chỉ email."
            )

        elif not is_valid_email(email):
            errors.append(
                "Địa chỉ email không đúng định dạng."
            )

        elif len(email) > 254:
            errors.append(
                "Địa chỉ email không được vượt quá 254 ký tự."
            )

        # Kiểm tra mật khẩu
        if not password:
            errors.append(
                "Vui lòng nhập mật khẩu."
            )

        elif len(password) < 8:
            errors.append(
                "Mật khẩu phải có ít nhất 8 ký tự."
            )

        elif len(password) > 128:
            errors.append(
                "Mật khẩu không được vượt quá 128 ký tự."
            )

        # Kiểm tra nhập lại mật khẩu
        if not confirm_password:
            errors.append(
                "Vui lòng nhập lại mật khẩu."
            )

        elif password != confirm_password:
            errors.append(
                "Hai mật khẩu không giống nhau."
            )

        database = get_database()

        # Kiểm tra email đã tồn tại
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
                flash(
                    error,
                    "error",
                )

            return render_template(
                "register.html",
                entered_username=username,
                entered_email=email,
            )

        password_hash = generate_password_hash(
            password
        )

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

        return redirect(
            url_for("login")
        )

    return render_template(
        "register.html"
    )


# ========================================
# ĐĂNG NHẬP
# ========================================

@app.route(
    "/login",
    methods=["GET", "POST"],
)
def login():

    if "user_id" in session:
        return redirect(
            url_for("dashboard")
        )

    if request.method == "POST":

        email = request.form.get(
            "email",
            "",
        ).strip().lower()

        password = request.form.get(
            "password",
            "",
        )

        errors = []

        if not email:
            errors.append(
                "Vui lòng nhập địa chỉ email."
            )

        elif not is_valid_email(email):
            errors.append(
                "Địa chỉ email không đúng định dạng."
            )

        if not password:
            errors.append(
                "Vui lòng nhập mật khẩu."
            )

        if errors:
            for error in errors:
                flash(
                    error,
                    "error",
                )

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

        if (
            user is None
            or not check_password_hash(
                user["password_hash"],
                password,
            )
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

        flash(
            "Đăng nhập thành công!",
            "success",
        )

        return redirect(
            url_for("dashboard")
        )

    return render_template(
        "login.html"
    )


# ========================================
# ĐĂNG XUẤT
# ========================================

@app.route(
    "/logout",
    methods=["POST"],
)
@login_required
def logout():

    session.clear()

    flash(
        "Bạn đã đăng xuất.",
        "success",
    )

    return redirect(
        url_for("login")
    )


# ========================================
# DASHBOARD
# ========================================

@app.route("/dashboard")
@login_required
def dashboard():

    database = get_database()

    posts = database.execute(
        """
        SELECT
            posts.id,
            posts.user_id,
            posts.image_filename,
            posts.caption,
            posts.created_at,
            users.username
        FROM posts
        JOIN users
            ON posts.user_id = users.id
        ORDER BY
            posts.created_at DESC,
            posts.id DESC
        """
    ).fetchall()

    return render_template(
        "dashboard.html",
        posts=posts,
    )


# ========================================
# ĐĂNG BÀI VIẾT
# ========================================

@app.route(
    "/posts/create",
    methods=["POST"],
)
@login_required
def create_post():

    caption = request.form.get(
        "caption",
        "",
    ).strip()

    image = request.files.get(
        "image"
    )

    # Kiểm tra nội dung trạng thái
    if len(caption) > 500:
        flash(
            "Trạng thái không được vượt quá 500 ký tự.",
            "error",
        )

        return redirect(
            url_for("dashboard")
        )

    # Kiểm tra người dùng đã chọn ảnh hay chưa
    if (
        image is None
        or image.filename == ""
    ):
        flash(
            "Vui lòng chọn một hình ảnh.",
            "error",
        )

        return redirect(
            url_for("dashboard")
        )

    # Kiểm tra định dạng ảnh
    if not allowed_image(
        image.filename
    ):
        flash(
            "Ảnh phải có định dạng PNG, JPG, JPEG, GIF hoặc WEBP.",
            "error",
        )

        return redirect(
            url_for("dashboard")
        )

    original_filename = secure_filename(
        image.filename
    )

    extension = original_filename.rsplit(
        ".",
        1,
    )[1].lower()

    unique_filename = (
        f"{session['user_id']}_"
        f"{uuid.uuid4().hex}."
        f"{extension}"
    )

    image_path = (
        UPLOAD_FOLDER
        / unique_filename
    )

    database = get_database()

    try:
        # Lưu ảnh vào static/uploads
        image.save(
            image_path
        )

        # Lưu bài viết vào database
        database.execute(
            """
            INSERT INTO posts (
                user_id,
                image_filename,
                caption
            )
            VALUES (?, ?, ?)
            """,
            (
                session["user_id"],
                unique_filename,
                caption,
            ),
        )

        database.commit()

    except (
        sqlite3.Error,
        OSError,
    ) as error:

        database.rollback()

        # Nếu lưu database thất bại thì xóa ảnh vừa lưu
        if image_path.exists():
            try:
                image_path.unlink()

            except OSError:
                pass

        app.logger.error(
            "Không thể đăng bài: %s",
            error,
        )

        flash(
            "Không thể đăng bài. Vui lòng thử lại.",
            "error",
        )

        return redirect(
            url_for("dashboard")
        )

    flash(
        "Đăng bài thành công!",
        "success",
    )

    return redirect(
        url_for("dashboard")
    )


# ========================================
# XÓA BÀI VIẾT
# ========================================

@app.route(
    "/posts/<int:post_id>/delete",
    methods=["POST"],
)
@login_required
def delete_post(post_id):

    database = get_database()

    post = database.execute(
        """
        SELECT
            id,
            user_id,
            image_filename
        FROM posts
        WHERE id = ?
        """,
        (post_id,),
    ).fetchone()

    # Không tìm thấy bài viết
    if post is None:
        flash(
            "Bài viết không tồn tại.",
            "error",
        )

        return redirect(
            url_for("dashboard")
        )

    # Không cho người dùng xóa bài của người khác
    if post["user_id"] != session["user_id"]:
        flash(
            "Bạn không có quyền xóa bài viết này.",
            "error",
        )

        return redirect(
            url_for("dashboard")
        )

    image_path = (
        UPLOAD_FOLDER
        / post["image_filename"]
    )

    try:
        # Xóa dữ liệu bài viết
        database.execute(
            """
            DELETE FROM posts
            WHERE id = ?
              AND user_id = ?
            """,
            (
                post_id,
                session["user_id"],
            ),
        )

        database.commit()

    except sqlite3.Error as error:
        database.rollback()

        app.logger.error(
            "Không thể xóa bài viết khỏi database: %s",
            error,
        )

        flash(
            "Không thể xóa bài viết. Vui lòng thử lại.",
            "error",
        )

        return redirect(
            url_for("dashboard")
        )

    # Chỉ xóa file ảnh sau khi database đã xóa thành công
    if image_path.exists():
        try:
            image_path.unlink()

        except OSError as error:
            app.logger.warning(
                "Đã xóa bài viết nhưng không thể xóa file ảnh %s: %s",
                image_path,
                error,
            )

    flash(
        "Đã xóa bài viết.",
        "success",
    )

    return redirect(
        url_for("dashboard")
    )


# ========================================
# XỬ LÝ FILE QUÁ LỚN
# ========================================

@app.errorhandler(413)
def file_too_large(error):

    flash(
        "Ảnh có dung lượng quá lớn. Dung lượng tối đa là 10 MB.",
        "error",
    )

    if "user_id" in session:
        return redirect(
            url_for("dashboard")
        )

    return redirect(
        url_for("login")
    )


# ========================================
# TRANG 404
# ========================================

@app.errorhandler(404)
def page_not_found(error):

    return (
        render_template(
            "404.html"
        ),
        404,
    )


# ========================================
# CHẠY ỨNG DỤNG
# ========================================

if __name__ == "__main__":
    app.run(
        debug=True
    )