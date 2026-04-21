"""
金丝猴智能平台 — 认证服务
FastAPI + SQLite + JWT | 邮箱验证码 + 强密码策略
启动: .venv/Scripts/python.exe auth_server.py
"""

import os, re, sqlite3, secrets, random, time, hashlib, smtplib, json
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.utils import formatdate, make_msgid, formataddr
from email.header import Header
from datetime import datetime, timedelta
from contextlib import contextmanager
from dotenv import load_dotenv

# 显式指定.env路径
load_dotenv(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".env"), override=True)

from fastapi import FastAPI, HTTPException, Depends, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, Field, field_validator
import jwt
import uvicorn

# ───────── 配置 ─────────
DB_PATH = os.path.join(os.path.dirname(__file__), "users.db")
SECRET_KEY = os.environ.get("JWT_SECRET", secrets.token_hex(32))
ALGORITHM = "HS256"
TOKEN_EXPIRE_HOURS = 24
CODE_EXPIRE_SECONDS = 300  # 验证码 5 分钟有效

# ═════ 邮箱 SMTP 配置（从 .env 文件读取，不在代码中暴露密码）═════
SMTP_HOST = os.getenv("SMTP_HOST", "smtp-mail.outlook.com")
SMTP_PORT = int(os.getenv("SMTP_PORT", "587"))
SMTP_USER = os.getenv("SMTP_USER", "")
SMTP_PASSWORD = os.getenv("SMTP_PASSWORD", "")
SMTP_FROM_NAME = os.getenv("SMTP_FROM_NAME", "金丝猴智能平台")

# Resend API Key（云端邮件服务）
RESEND_API_KEY = os.getenv("RESEND_API_KEY", "")

# 调试：打印环境变量是否加载成功
print(f"[SMTP 配置检查] HOST={SMTP_HOST}, PORT={SMTP_PORT}, USER={SMTP_USER}, 密码已设置={bool(SMTP_PASSWORD)}, FROM_NAME={SMTP_FROM_NAME}")

# ───────── 数据库 ─────────
def init_db():
    with get_db() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                username    TEXT UNIQUE NOT NULL,
                email       TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                created_at  TEXT NOT NULL DEFAULT (datetime('now'))
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS verify_codes (
                id         INTEGER PRIMARY KEY AUTOINCREMENT,
                email      TEXT NOT NULL,
                code       TEXT NOT NULL,
                created_at REAL NOT NULL,
                used       INTEGER NOT NULL DEFAULT 0
            )
        """)

@contextmanager
def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()

# ───────── 密码工具 ─────────
def hash_password(password: str) -> str:
    salt = secrets.token_hex(16)
    h = hashlib.sha256((salt + password).encode()).hexdigest()
    return f"{salt}${h}"

def verify_password(password: str, stored: str) -> bool:
    salt, h = stored.split("$", 1)
    return hashlib.sha256((salt + password).encode()).hexdigest() == h

PASSWORD_RE = re.compile(
    r'^(?=.*[a-zA-Z])(?=.*\d)(?=.*[!@#$%^&*()_+\-=\[\]{};:\'",./<>?\\|`~])'
    r'.{8,64}$'
)

def check_strong_password(pw: str):
    if not PASSWORD_RE.match(pw):
        raise HTTPException(
            status_code=422,
            detail="密码需8-64位，包含字母、数字和特殊符号"
        )

# ───────── 数据模型 ─────────
# ───────── 邮件发送 ─────────
def build_email_html(code: str) -> str:
    return f"""<!DOCTYPE html>
<html lang="zh-CN"><head><meta charset="utf-8"></head>
<body style="margin:0;padding:0;background:#f4f4f4;">
<table width="100%" cellpadding="0" cellspacing="0" style="background:#f4f4f4;padding:20px 0;">
  <tr><td align="center">
    <table width="460" cellpadding="0" cellspacing="0" style="background:#ffffff;border:1px solid #dedede;">
      <tr><td style="background:#1a4a3a;padding:28px 24px;text-align:center;">
        <span style="color:#ffffff;font-size:20px;font-family:SimHei,sans-serif;">金丝猴智能平台</span>
      </td></tr>
      <tr><td style="padding:28px 24px;font-family:SimSun,sans-serif;font-size:14px;color:#333333;line-height:1.6;">
        <p>您好，</p>
        <p>您正在进行账号验证，请使用以下验证码完成操作：</p>
        <table width="100%" cellpadding="0" cellspacing="0"><tr><td align="center" style="padding:16px 0;">
          <span style="font-size:32px;font-weight:bold;letter-spacing:6px;color:#1a4a3a;font-family:Consolas,monospace;">{code}</span>
        </td></tr></table>
        <p>验证码 5 分钟内有效，请勿将此验证码告知他人。</p>
        <p style="color:#999999;font-size:12px;margin-top:24px;">如果您没有进行相关操作，请忽略此邮件。</p>
      </td></tr>
      <tr><td style="background:#f9f9f9;padding:14px 24px;text-align:center;border-top:1px solid #eeeeee;">
        <span style="color:#aaaaaa;font-size:11px;">此邮件由系统发送 请勿直接回复</span>
      </td></tr>
    </table>
  </td></tr>
</table>
</body></html>
"""

def send_email(to_email: str, code: str) -> bool:
    """Send verification code via Resend API or SMTP. Returns True on success."""
    
    # 优先使用 Resend API（云端）
    if RESEND_API_KEY:
        try:
            import requests
            res = requests.post(
                "https://api.resend.com/emails",
                headers={
                    "Authorization": f"Bearer {RESEND_API_KEY}",
                    "Content-Type": "application/json"
                },
                json={
                    "from": f"{SMTP_FROM_NAME} <onboarding@resend.dev>",
                    "to": [to_email],
                    "subject": "邮箱验证 - 金丝猴智能平台",
                    "html": build_email_html(code)
                },
                timeout=10
            )
            if res.status_code == 200:
                print(f"[Resend 发送成功] {to_email}")
                return True
            else:
                print(f"[Resend 发送失败] {res.status_code}: {res.text}")
                return False
        except Exception as e:
            print(f"[Resend 异常] {e}")
            return False
    
    # 回退到 SMTP（本地）
    if not SMTP_USER or not SMTP_PASSWORD:
        print(f"[SMTP 未配置] 验证码: {code} -> {to_email}")
        return False

    msg = MIMEMultipart("alternative")
    msg["Subject"] = Header("邮箱验证 - 金丝猴智能平台", "utf-8")
    msg["From"] = formataddr((str(Header(SMTP_FROM_NAME, "utf-8")), SMTP_USER))
    msg["To"] = to_email
    msg["Date"] = formatdate(localtime=True)
    msg["Message-ID"] = make_msgid(domain=SMTP_USER.split("@")[-1] if SMTP_USER else "example.com")
    msg["Reply-To"] = SMTP_USER

    plain = f"您好，您正在进行账号验证。验证码：{code}，5分钟内有效。如非本人操作请忽略。"
    html = build_email_html(code)
    msg.attach(MIMEText(plain, "plain", "utf-8"))
    msg.attach(MIMEText(html, "html", "utf-8"))

    try:
        if SMTP_PORT == 465:
            # QQ邮箱等用 SSL
            with smtplib.SMTP_SSL(SMTP_HOST, SMTP_PORT, timeout=10) as smtp:
                smtp.login(SMTP_USER, SMTP_PASSWORD)
                smtp.sendmail(SMTP_USER, to_email, msg.as_string())
        else:
            # Hotmail/Outlook/Gmail 等用 STARTTLS
            with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=10) as smtp:
                smtp.ehlo()
                smtp.starttls()
                smtp.ehlo()
                smtp.login(SMTP_USER, SMTP_PASSWORD)
                smtp.sendmail(SMTP_USER, to_email, msg.as_string())
        print(f"[✓ 邮件已发送] {to_email}")
        return True
    except Exception as e:
        print(f"[✗ 邮件发送失败] {to_email}: {e}")
        return False

EMAIL_RE = re.compile(r'^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$')

class SendCodeReq(BaseModel):
    email: str

    @field_validator('email')
    @classmethod
    def validate_email(cls, v):
        if not EMAIL_RE.match(v):
            raise ValueError('邮箱格式不正确')
        return v.lower().strip()

class RegisterReq(BaseModel):
    username: str = Field(..., min_length=2, max_length=20)
    email: str
    password: str = Field(..., min_length=8, max_length=64)
    code: str = Field(..., min_length=6, max_length=6)

    @field_validator('email')
    @classmethod
    def validate_email(cls, v):
        if not EMAIL_RE.match(v):
            raise ValueError('邮箱格式不正确')
        return v.lower().strip()

class LoginReq(BaseModel):
    username: str
    password: str

class TokenResp(BaseModel):
    token: str
    username: str

# ───────── JWT ─────────
def create_token(username: str) -> str:
    return jwt.encode(
        {"sub": username, "exp": datetime.utcnow() + timedelta(hours=TOKEN_EXPIRE_HOURS), "iat": datetime.utcnow()},
        SECRET_KEY, algorithm=ALGORITHM
    )

security = HTTPBearer()

def get_current_user(cred: HTTPAuthorizationCredentials = Depends(security)) -> str:
    try:
        return jwt.decode(cred.credentials, SECRET_KEY, algorithms=[ALGORITHM])["sub"]
    except jwt.ExpiredSignatureError:
        raise HTTPException(401, "登录已过期，请重新登录")
    except jwt.InvalidTokenError:
        raise HTTPException(401, "无效的令牌")

# ───────── 应用 ─────────
app = FastAPI(title="金丝猴平台认证服务")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

@app.on_event("startup")
def startup():
    init_db()

@app.get("/", summary="首页")
def index():
    return FileResponse(os.path.join(os.path.dirname(__file__), "golden_monkey14.html"))

# ───────── 发送验证码 ─────────
@app.post("/api/send-code", summary="发送邮箱验证码")
def send_code(req: SendCodeReq):
    email = req.email

    with get_db() as conn:
        # 检查邮箱是否已注册
        if conn.execute("SELECT id FROM users WHERE email = ?", (email,)).fetchone():
            raise HTTPException(409, "该邮箱已注册")

        # 频率限制：60秒内只能发一次
        recent = conn.execute(
            "SELECT created_at FROM verify_codes WHERE email = ? ORDER BY id DESC LIMIT 1",
            (email,)
        ).fetchone()
        if recent and time.time() - recent["created_at"] < 60:
            raise HTTPException(429, "发送太频繁，请60秒后重试")

        code = f"{random.randint(0, 999999):06d}"
        conn.execute(
            "INSERT INTO verify_codes (email, code, created_at) VALUES (?, ?, ?)",
            (email, code, time.time())
        )

    # 发送邮件
    email_sent = send_email(email, code)

    if email_sent:
        return {"message": "验证码已发送至您的邮箱，请查收"}
    else:
        # SMTP 未配置时回退演示模式
        # return {"message": "验证码已发送", "hint": f"（演示模式）验证码: {code}"}
        raise HTTPException(500, "邮件发送失败，请检查邮箱配置或联系管理员")

# ───────── 注册 ─────────
@app.post("/api/register", response_model=TokenResp, summary="用户注册")
def register(req: RegisterReq):
    check_strong_password(req.password)
    email = req.email

    with get_db() as conn:
        if conn.execute("SELECT id FROM users WHERE username = ?", (req.username,)).fetchone():
            raise HTTPException(409, "用户名已存在")
        if conn.execute("SELECT id FROM users WHERE email = ?", (email,)).fetchone():
            raise HTTPException(409, "该邮箱已注册")

        # 验证码校验
        row = conn.execute(
            "SELECT id, code, created_at, used FROM verify_codes WHERE email = ? ORDER BY id DESC LIMIT 1",
            (email,)
        ).fetchone()
        if not row:
            raise HTTPException(400, "请先获取验证码")
        if row["used"]:
            raise HTTPException(400, "验证码已使用，请重新获取")
        if time.time() - row["created_at"] > CODE_EXPIRE_SECONDS:
            raise HTTPException(400, "验证码已过期，请重新获取")
        if row["code"] != req.code:
            raise HTTPException(400, "验证码错误")

        conn.execute("UPDATE verify_codes SET used = 1 WHERE id = ?", (row["id"],))
        conn.execute(
            "INSERT INTO users (username, email, password_hash) VALUES (?, ?, ?)",
            (req.username, email, hash_password(req.password))
        )

    return TokenResp(token=create_token(req.username), username=req.username)

# ───────── 登录 ─────────
@app.post("/api/login", response_model=TokenResp, summary="用户登录")
def login(req: LoginReq):
    with get_db() as conn:
        user = conn.execute(
            "SELECT username, password_hash FROM users WHERE username = ?",
            (req.username,)
        ).fetchone()

    if not user or not verify_password(req.password, user["password_hash"]):
        raise HTTPException(401, "用户名或密码错误")

    return TokenResp(token=create_token(user["username"]), username=user["username"])

# ───────── 当前用户 ─────────
@app.get("/api/me", summary="获取当前用户信息")
def me(username: str = Depends(get_current_user)):
    return {"username": username}

# ───────── 知识问答（DeepSeek）─────────
class AskReq(BaseModel):
    question: str = Field(..., min_length=1, max_length=1000)

@app.post("/api/ask", summary="知识问答")
def ask(req: AskReq):
    from openai import OpenAI
    api_key = os.environ.get('DEEPSEEK_API_KEY')
    if not api_key:
        raise HTTPException(500, "DeepSeek API Key 未配置")

    client = OpenAI(api_key=api_key, base_url="https://api.deepseek.com")

    system_prompt = (
        "你是金丝猴领域的顶级研究专家。直接给出答案，无需铺垫和客套。"
        "总字数严格控制在50-200字，每句话都必须有实质信息量。"
        "可用**加粗**标注关键术语，用##标注小段落标题（如有必要），用-列举要点。"
        "禁止：重复问题、过渡性废话、总结句、'综上所述'等套话。"
        "使用专业术语但确保一定可读性，体现学术深度。"
    )

    response = client.chat.completions.create(
        model="deepseek-reasoner",
        messages=[
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": req.question},
        ],
        stream=False,
        extra_body={"enable_search": True, "search_strategy": "turbo"}
    )

    answer = response.choices[0].message.content
    return {"answer": answer}

# ───────── 启动 ─────────
if __name__ == "__main__":
    # 如果在云端运行就用云端分配的端口，如果在本地运行默认用 8000
    port = int(os.environ.get("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port, log_level="info")
