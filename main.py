# database, routing, session
# -*- coding -*-
"""
主程序：Flask + SQLite
实现功能：
1) 注册：任意用户名 + 自设密码（存哈希）
2) 登录：校验哈希，成功后写 session
3) 欢迎页、登出
4) （可选）简易博客路由，便于你登录后有可视交互
"""

import sqlite3                       # Python 内置 SQLite 模块
from flask import (
    Flask, render_template, request,  # Flask 基础组件
    redirect, url_for, flash, session, abort
)
from werkzeug.security import (
    generate_password_hash,           # 生成密码哈希
    check_password_hash               # 校验密码与哈希
)
from datetime import timedelta        # 设置 session 有效期

# ------------------ Flask 基本配置 ------------------
app = Flask(__name__)

# 用于加密 session 的密钥（务必改成随机长字符串，且不要公开）
app.secret_key = "replace-with-a-better-secret"

# “记住登录”时长（配合 session.permanent=True）
app.permanent_session_lifetime = timedelta(days=7)


# ------------------ 数据库帮助函数 ------------------
def get_db():
    """返回一个连接到项目根目录 database.db 的连接对象"""
    conn = sqlite3.connect("database.db")
    # 返回 Row 对象，便于通过列名访问，如 row["username"]
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    """若数据表不存在则创建；并在空库时插入一篇欢迎文章"""
    with get_db() as conn:
        # 用户表：username 唯一；password_hash 存放哈希值（不存明文）
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                created TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
            """
        )

        # 可选的 posts 表：用于示例文章（方便你登录后有内容可发/看）
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS posts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                title TEXT NOT NULL,
                content TEXT NOT NULL,
                created TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
            """
        )

        # 如果 posts 表是空的，播种一篇默认文章，便于首页展示
        cur = conn.execute("SELECT COUNT(*) AS c FROM posts")
        if cur.fetchone()["c"] == 0:
            conn.execute(
                "INSERT INTO posts (title, content) VALUES (?, ?)",
                ("Hello, I'm Jin!", "This is your first post.")
            )
        conn.commit()


@app.before_request
def before():
    """每个请求前确保数据库初始化过（建表/播种只会在首次执行）"""
    init_db()


# ------------------ 自定义装饰器：需登录的路由 ------------------
def login_required(view):
    """如果没登录，重定向到 /login；否则执行原视图函数"""
    def wrapped(*args, **kwargs):
        if not session.get("user_id"):
            flash("Please log in first.")
            return redirect(url_for("login"))
        return view(*args, **kwargs)
    wrapped.__name__ = view.__name__   # 维持函数名，避免调试/装饰器问题
    return wrapped


# ------------------ 基础路由：主页 ------------------
@app.route("/")
def index():
    """
    首页：不强制登录
    - 展示最新文章列表（可选模块）
    - 顶部导航根据是否登录显示不同菜单
    """
    with get_db() as conn:
        posts = conn.execute(
            "SELECT * FROM posts ORDER BY created DESC"
        ).fetchall()
    return render_template("index.html",
                           posts=posts,
                           username=session.get("username"))


# ------------------ 注册 ------------------
@app.route("/register", methods=["GET", "POST"])
def register():
    """
    GET：显示注册表单
    POST：接收 username/password；校验 & 写入数据库（保存哈希）
    """
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "").strip()

        # 基本校验：不能为空
        if not username or not password:
            flash("Username and password are required.")
            return render_template("register.html")

        # 为密码生成哈希（默认使用 PBKDF2:SHA256）
        pw_hash = generate_password_hash(password)

        # 写入数据库（username 唯一，重复会抛 IntegrityError）
        try:
            with get_db() as conn:
                conn.execute(
                    "INSERT INTO users (username, password_hash) VALUES (?, ?)",
                    (username, pw_hash)
                )
                conn.commit()
            flash("Registration successful. You can now log in.")
            return redirect(url_for("login"))
        except sqlite3.IntegrityError:
            flash("Username already taken. Try another one.")
            return render_template("register.html")

    # GET：渲染注册页面
    return render_template("register.html")


# ------------------ 登录 ------------------
@app.route("/login", methods=["GET", "POST"])
def login():
    """
    GET：显示登录表单
    POST：按用户名查用户 → 校验密码与哈希 → 写 session → 跳 /welcome
    """
    error = None
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "").strip()

        # 从数据库按用户名取记录
        with get_db() as conn:
            user = conn.execute(
                "SELECT * FROM users WHERE username = ?",
                (username,)
            ).fetchone()

        # 校验失败：用户名不存在或密码不匹配
        if not user or not check_password_hash(user["password_hash"], password):
            error = "Invalid Credentials. Please try again."
        else:
            # 登录成功：记住用户
            session.permanent = True  # 结合 app.permanent_session_lifetime
            session["user_id"] = user["id"]
            session["username"] = user["username"]
            flash("Login successful.")
            return redirect(url_for("welcome"))

    # GET 或校验失败
    return render_template("login.html", error=error)


# ------------------ 欢迎页（需登录） ------------------
@app.route("/welcome")
@login_required
def welcome():
    """登录成功后显示欢迎页"""
    return render_template("welcome.html",
                           username=session.get("username"))


# ------------------ 登出 ------------------
@app.route("/logout")
def logout():
    """清除 session 并回到登录页"""
    session.pop("user_id", None)
    session.pop("username", None)
    flash("You have been logged out.")
    return redirect(url_for("login"))


# ------------------ 以下为可选：简易博客路由 ------------------
@app.route("/<int:post_id>")
def post_detail(post_id):
    """查看单篇文章（不强制登录）"""
    with get_db() as conn:
        post = conn.execute(
            "SELECT * FROM posts WHERE id = ?",
            (post_id,)
        ).fetchone()
    if post is None:
        abort(404)
    return render_template("post.html",
                           post=post,
                           username=session.get("username"))


@app.route("/create", methods=["GET", "POST"])
@login_required
def create():
    """创建文章（需登录）"""
    if request.method == "POST":
        title = request.form.get("title", "").strip()
        content = request.form.get("content", "").strip()
        if not title or not content:
            flash("Title and content are required.")
        else:
            with get_db() as conn:
                conn.execute(
                    "INSERT INTO posts (title, content) VALUES (?, ?)",
                    (title, content)
                )
                conn.commit()
            flash("Post created.")
            return redirect(url_for("index"))
    return render_template("create.html", username=session.get("username"))


@app.route("/<int:post_id>/edit", methods=["GET", "POST"])
@login_required
def edit(post_id):
    """编辑文章（需登录）"""
    with get_db() as conn:
        post = conn.execute(
            "SELECT * FROM posts WHERE id = ?",
            (post_id,)
        ).fetchone()
    if post is None:
        abort(404)

    if request.method == "POST":
        title = request.form.get("title", "").strip()
        content = request.form.get("content", "").strip()
        if not title or not content:
            flash("Both fields required.")
        else:
            with get_db() as conn:
                conn.execute(
                    "UPDATE posts SET title=?, content=? WHERE id=?",
                    (title, content, post_id)
                )
                conn.commit()
            flash("Post updated.")
            return redirect(url_for("post_detail", post_id=post_id))

    return render_template("edit.html",
                           post=post,
                           username=session.get("username"))


@app.route("/<int:post_id>/delete", methods=["POST"])
@login_required
def delete(post_id):
    """删除文章（需登录，POST 触发，带确认提示）"""
    with get_db() as conn:
        conn.execute("DELETE FROM posts WHERE id = ?", (post_id,))
        conn.commit()
    flash("Post deleted.")
    return redirect(url_for("index"))


# ------------------ 程序入口 ------------------
if __name__ == "__main__":
    # 开发模式：debug=True 方便看到报错与自动重载
    app.run(debug=True)
