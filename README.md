#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import datetime
import hmac
import html
import os
import re
import shutil
import sqlite3
import threading
import time
import urllib.parse
from collections import defaultdict
from http.server import BaseHTTPRequestHandler, HTTPServer

import requests

# ------------------------------------------------------------
# 1. Render settings
# ------------------------------------------------------------
PORT = int(os.environ.get("PORT", 8080))
ADMIN_SECRET = os.environ.get("ADMIN_SECRET", "change-me-render-admin-secret")

if ADMIN_SECRET == "change-me-render-admin-secret":
    print("[!] WARNING: set ADMIN_SECRET in Render Environment Variables before production use.")

# ------------------------------------------------------------
# 2. SQLite database
# ------------------------------------------------------------
DB_NAME = os.environ.get("DB_NAME", "honeypot.db")


def init_database():
    # Render free instances use an ephemeral filesystem. This SQLite file and
    # local text logs/backups can be reset after redeploys, restarts, or instance moves.
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    c.execute(
        """CREATE TABLE IF NOT EXISTS attacks (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ip TEXT NOT NULL,
        timestamp TEXT NOT NULL,
        username TEXT,
        password TEXT,
        user_agent TEXT,
        status TEXT
    )"""
    )
    c.execute(
        """CREATE TABLE IF NOT EXISTS blocked_ips (
        ip TEXT PRIMARY KEY,
        blocked_at TEXT NOT NULL,
        reason TEXT
    )"""
    )
    conn.commit()
    conn.close()


init_database()


def save_attack(ip, username, password, user_agent, status):
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    c.execute(
        """INSERT INTO attacks (ip, timestamp, username, password, user_agent, status)
                 VALUES (?, ?, ?, ?, ?, ?)""",
        (ip, datetime.datetime.now().isoformat(), username, password, user_agent, status),
    )
    conn.commit()
    conn.close()

    with open("honeypot_logs.txt", "a", encoding="utf-8", errors="ignore") as f:
        f.write(
            f"{datetime.datetime.now()} | IP={ip} | USER={username} | "
            f"PASS={password} | UA={user_agent} | STATUS={status}\n"
        )


def is_ip_blocked(ip):
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    c.execute("SELECT 1 FROM blocked_ips WHERE ip = ?", (ip,))
    result = c.fetchone() is not None
    conn.close()
    return result


def block_ip_permanently(ip, reason="Manual block"):
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    try:
        c.execute(
            "INSERT INTO blocked_ips (ip, blocked_at, reason) VALUES (?, ?, ?)",
            (ip, datetime.datetime.now().isoformat(), reason),
        )
        conn.commit()
    except sqlite3.IntegrityError:
        pass
    conn.close()


def unblock_ip(ip):
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    c.execute("DELETE FROM blocked_ips WHERE ip = ?", (ip,))
    conn.commit()
    conn.close()


# ------------------------------------------------------------
# 3. Brute-force protection
# ------------------------------------------------------------
failed_attempts = defaultdict(list)
MAX_FAILED_ATTEMPTS = 5
BLOCK_DURATION = 300

# ------------------------------------------------------------
# 4. Geo IP
# ------------------------------------------------------------
geo_cache = {}


def get_ip_country(ip):
    if ip.startswith("127."):
        return "Localhost"

    if ip.startswith("192.168.") or ip.startswith("10."):
        return "Local Network"

    if ip in geo_cache:
        return geo_cache[ip]

    try:
        response = requests.get(f"http://ip-api.com/json/{ip}", timeout=3)
        data = response.json()
        country = data.get("country", "Unknown")
        geo_cache[ip] = country
        return country
    except Exception:
        return "Unknown"


def is_temporarily_blocked(ip):
    now = time.time()
    failed_attempts[ip] = [t for t in failed_attempts[ip] if now - t < BLOCK_DURATION]
    return len(failed_attempts[ip]) >= MAX_FAILED_ATTEMPTS


def add_failed_attempt(ip):
    failed_attempts[ip].append(time.time())


# ------------------------------------------------------------
# 5. Attack detection
# ------------------------------------------------------------
def detect_attack_type(text):
    text = text.lower()

    sql_patterns = ["union select", "select * from", "drop table", "--", "or 1=1"]
    xss_patterns = ["<script", "javascript:", "onerror=", "alert("]
    traversal_patterns = ["../", "..\\", "/etc/passwd"]
    command_patterns = ["cmd.exe", "/bin/sh", "powershell", "wget ", "curl "]

    for pattern in sql_patterns:
        if pattern in text:
            return "SQL_INJECTION"

    for pattern in xss_patterns:
        if pattern in text:
            return "XSS_ATTACK"

    for pattern in traversal_patterns:
        if pattern in text:
            return "PATH_TRAVERSAL"

    for pattern in command_patterns:
        if pattern in text:
            return "COMMAND_INJECTION"

    return "SUSPICIOUS_ATTACK"


def is_suspicious(text):
    patterns = [
        r"['\";<>-]",
        r"\.\./",
        r"etc/passwd",
        r"bin/sh",
        r"select.*from",
        r"union.*select",
        r"<script",
        r"javascript:",
        r"--",
        r"\\x[0-9a-fA-F]{2}",
    ]
    for pattern in patterns:
        if re.search(pattern, text, re.IGNORECASE):
            return True
    return False


# ------------------------------------------------------------
# 6. HTML templates
# ------------------------------------------------------------
LOGIN_PAGE = """<!DOCTYPE html>
<html lang="ru">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Государственный портал</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            display: flex;
            justify-content: center;
            align-items: center;
        }
        .card {
            background: white;
            border-radius: 15px;
            width: 450px;
            max-width: calc(100vw - 32px);
            padding: 40px;
            box-shadow: 0 20px 40px rgba(0,0,0,0.1);
            animation: fadeIn 0.5s ease-in;
        }
        @keyframes fadeIn {
            from { opacity: 0; transform: translateY(-20px); }
            to { opacity: 1; transform: translateY(0); }
        }
        h1 { text-align: center; color: #333; margin-bottom: 10px; }
        .subtitle { text-align: center; color: #666; margin-bottom: 30px; font-size: 14px; }
        input {
            width: 100%;
            padding: 12px;
            margin: 8px 0 20px;
            border: 2px solid #e0e0e0;
            border-radius: 8px;
            font-size: 16px;
            transition: all 0.3s;
        }
        input:focus {
            outline: none;
            border-color: #667eea;
            box-shadow: 0 0 0 3px rgba(102,126,234,0.1);
        }
        button {
            width: 100%;
            padding: 12px;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            border: none;
            border-radius: 8px;
            font-size: 16px;
            font-weight: bold;
            cursor: pointer;
            transition: transform 0.2s;
        }
        button:hover { transform: translateY(-2px); }
        .footer {
            margin-top: 20px;
            text-align: center;
            font-size: 12px;
            color: #999;
        }
    </style>
</head>
<body>
<div class="card">
    <h1>🏛️ ГосПортал</h1>
    <div class="subtitle">Единая система идентификации и аутентификации</div>
    <form method="POST" action="/auth">
        <input type="text" name="login" placeholder="Логин (ИНН/Email)" required>
        <input type="password" name="password" placeholder="Пароль" required>
        <button type="submit">Войти в систему</button>
    </form>
    <div class="footer">🔒 Все попытки доступа логируются</div>
</div>
</body>
</html>"""

ERROR_PAGE = """<!DOCTYPE html>
<html lang="ru">
<head>
    <meta charset="UTF-8">
    <title>Ошибка авторизации</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            display: flex;
            justify-content: center;
            align-items: center;
        }
        .card {
            background: white;
            border-radius: 15px;
            width: 450px;
            max-width: calc(100vw - 32px);
            padding: 40px;
            text-align: center;
            box-shadow: 0 20px 40px rgba(0,0,0,0.1);
            animation: shake 0.5s;
        }
        @keyframes shake {
            0%, 100% { transform: translateX(0); }
            25% { transform: translateX(-10px); }
            75% { transform: translateX(10px); }
        }
        .icon { font-size: 64px; margin-bottom: 20px; }
        h2 { color: #c33; margin-bottom: 10px; }
        p { color: #666; margin: 10px 0; }
        a {
            display: inline-block;
            margin-top: 20px;
            padding: 10px 20px;
            background: #667eea;
            color: white;
            text-decoration: none;
            border-radius: 8px;
            transition: background 0.3s;
        }
        a:hover { background: #5a67d8; }
    </style>
</head>
<body>
<div class="card">
    <div class="icon">⚠️</div>
    <h2>Неверный логин или пароль</h2>
    <p>Попытка входа зафиксирована. Ваш IP добавлен в журнал безопасности.</p>
    <a href="/">Вернуться на главную</a>
</div>
</body>
</html>"""

ADMIN_PAGE_TEMPLATE = """<!DOCTYPE html>
<html lang="ru">
<head>
    <meta charset="UTF-8">
    <meta http-equiv="refresh" content="15;url=/admin?secret={admin_secret_url}">
    <title>Панель мониторинга Honeypot</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{
            background: #0a0a0a;
            color: #0f0;
            font-family: 'Courier New', monospace;
            padding: 20px;
        }}
        h1, h2 {{
            border-bottom: 1px solid #0f0;
            padding-bottom: 10px;
            margin: 20px 0;
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
            margin: 20px 0;
        }}
        th, td {{
            border: 1px solid #0f0;
            padding: 10px;
            text-align: left;
            vertical-align: top;
            word-break: break-word;
        }}
        th {{
            background: #1a1a1a;
        }}
        .btn-block, .btn-unblock {{
            background: none;
            border: 1px solid;
            padding: 5px 12px;
            cursor: pointer;
            font-family: monospace;
            font-weight: bold;
            border-radius: 5px;
            transition: all 0.2s;
        }}
        .btn-block {{
            color: #f00;
            border-color: #f00;
        }}
        .btn-block:hover {{
            background: #f00;
            color: #000;
        }}
        .btn-unblock {{
            color: #0f0;
            border-color: #0f0;
        }}
        .btn-unblock:hover {{
            background: #0f0;
            color: #000;
        }}
        .stats {{
            display: flex;
            gap: 20px;
            margin: 20px 0;
            flex-wrap: wrap;
        }}
        .stat {{
            background: #1a1a1a;
            padding: 15px 20px;
            border-radius: 10px;
            border-left: 4px solid #0f0;
        }}
        .stat-value {{
            font-size: 28px;
            font-weight: bold;
            margin-top: 5px;
        }}
        .refresh-btn {{
            background: #0f0;
            color: #1a1a1a;
            border: none;
            padding: 10px 20px;
            cursor: pointer;
            font-weight: bold;
            border-radius: 5px;
            margin-bottom: 10px;
        }}
        .refresh-btn:hover {{
            background: #0c0;
        }}
    </style>
</head>
<body>
<h1>🔒 Honeypot Security Monitor</h1>
<button class="refresh-btn" onclick="location.href='/admin?secret={admin_secret_js}'">⟳ Обновить</button>
<div class="stats">
    <div class="stat">📊 Всего атак<br><span class="stat-value">{total_attacks}</span></div>
    <div class="stat">🌍 Уникальных IP<br><span class="stat-value">{unique_ips}</span></div>
    <div class="stat">🚫 Заблокировано<br><span class="stat-value">{blocked_count}</span></div>
</div>
<h2>🔥 Топ атакующих IP</h2>
<table>
    <thead>
        <tr><th>IP адрес</th><th>Количество атак</th><th>Последняя активность</th><th>Геолокация</th></tr>
    </thead>
    <tbody>{top_ips_rows}</tbody>
</table>
<h2>🚫 Постоянно заблокированные IP</h2>
<table>
    <thead>
        <tr><th>IP адрес</th><th>Дата блокировки</th><th>Причина</th><th>Действие</th></tr>
    </thead>
    <tbody>{blocked_rows}</tbody>
</table>
<h2>📋 Последние 50 попыток входа</h2>
<table>
    <thead>
        <tr><th>Время</th><th>IP</th><th>Логин</th><th>Пароль</th><th>User-Agent</th><th>Статус</th><th>Блокировка</th></tr>
    </thead>
    <tbody>{attack_rows}</tbody>
</table>
</body>
</html>"""


# ------------------------------------------------------------
# 7. Backup system
# ------------------------------------------------------------
def create_backup():
    try:
        if not os.path.exists("backups"):
            os.makedirs("backups")

        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        db_backup = f"backups/honeypot_{timestamp}.db"
        txt_backup = f"backups/logs_{timestamp}.txt"

        if os.path.exists(DB_NAME):
            shutil.copy(DB_NAME, db_backup)

        if os.path.exists("honeypot_logs.txt"):
            shutil.copy("honeypot_logs.txt", txt_backup)

        print(f"[+] Backup created: {timestamp}")
    except Exception as e:
        print(f"[!] Backup error: {e}")


def backup_scheduler():
    while True:
        time.sleep(21600)
        create_backup()


# ------------------------------------------------------------
# 8. HTTP handler
# ------------------------------------------------------------
class HoneypotHandler(BaseHTTPRequestHandler):
    def get_client_ip(self):
        ip = self.client_address[0]
        if "X-Forwarded-For" in self.headers:
            ip = self.headers["X-Forwarded-For"].split(",")[0].strip()
        elif "X-Real-IP" in self.headers:
            ip = self.headers["X-Real-IP"]
        elif "CF-Connecting-IP" in self.headers:
            ip = self.headers["CF-Connecting-IP"]
        elif "True-Client-IP" in self.headers:
            ip = self.headers["True-Client-IP"]
        return ip

    def log_message(self, format, *args):
        pass

    def send_html_response(self, status_code, content):
        self.send_response(status_code)
        self.send_header("Content-type", "text/html; charset=utf-8")
        self.end_headers()
        self.wfile.write(content.encode("utf-8"))

    def is_admin_authorized(self, query):
        secret = urllib.parse.parse_qs(query).get("secret", [""])[0]
        return hmac.compare_digest(secret, ADMIN_SECRET)

    def admin_url(self):
        return "/admin?secret=" + urllib.parse.quote(ADMIN_SECRET)

    def require_admin(self, query):
        if self.is_admin_authorized(query):
            return True
        self.send_html_response(403, "<h1>Access denied</h1><p>Invalid admin secret.</p>")
        return False

    def do_GET(self):
        ip = self.get_client_ip()
        parsed_url = urllib.parse.urlparse(self.path)
        path = parsed_url.path

        if path == "/healthz":
            self.send_html_response(200, "OK")
            return

        if path == "/admin":
            if not self.require_admin(parsed_url.query):
                return
            self.show_admin_page()
            return

        if is_ip_blocked(ip) or is_temporarily_blocked(ip):
            self.send_html_response(403, "<h1>Доступ запрещён</h1><p>Ваш IP заблокирован.</p>")
            return

        self.send_html_response(200, LOGIN_PAGE)

    def show_admin_page(self):
        conn = sqlite3.connect(DB_NAME)
        c = conn.cursor()

        c.execute("SELECT COUNT(*) FROM attacks")
        total_attacks = c.fetchone()[0]
        c.execute("SELECT COUNT(DISTINCT ip) FROM attacks")
        unique_ips = c.fetchone()[0]
        c.execute("SELECT COUNT(*) FROM blocked_ips")
        blocked_count = c.fetchone()[0]

        c.execute(
            """SELECT ip, COUNT(*) as cnt, MAX(timestamp) as last_ts
               FROM attacks
               GROUP BY ip
               ORDER BY cnt DESC
               LIMIT 20"""
        )
        top_ips = c.fetchall()
        top_ips_rows = ""
        for ip_addr, cnt, last_ts in top_ips:
            safe_ip = html.escape(ip_addr or "")
            country = html.escape(get_ip_country(ip_addr or ""))
            last_str = html.escape(last_ts[:19] if last_ts else "-")
            top_ips_rows += f"<tr><td>{safe_ip}</td><td>{cnt}</td><td>{last_str}</td><td>{country}</td></tr>"

        c.execute("SELECT ip, blocked_at, reason FROM blocked_ips ORDER BY blocked_at DESC")
        blocked_ips = c.fetchall()
        blocked_rows = ""
        for ip_addr, blocked_at, reason in blocked_ips:
            safe_ip = html.escape(ip_addr or "")
            safe_blocked_at = html.escape(blocked_at or "")
            reason_text = html.escape(reason if reason else "-")
            blocked_rows += f"<tr><td>{safe_ip}</td><td>{safe_blocked_at}</td><td>{reason_text}</td>"
            blocked_rows += (
                f"<td><form method='POST' action='/admin/unblock?secret={urllib.parse.quote(ADMIN_SECRET)}' "
                "style='display:inline;'>"
                f"<input type='hidden' name='ip' value='{safe_ip}'>"
                "<button class='btn-unblock' type='submit'>Разблокировать</button></form></td></tr>"
            )

        c.execute(
            """SELECT timestamp, ip, username, password, user_agent, status
               FROM attacks
               ORDER BY timestamp DESC
               LIMIT 50"""
        )
        attacks = c.fetchall()
        attack_rows = ""
        for ts, ip_addr, username, password, ua, status in attacks:
            ua = ua or ""
            ua_short = (ua[:30] + "...") if len(ua) > 30 else ua
            safe_ip = html.escape(ip_addr or "")
            attack_rows += (
                f"<tr><td>{html.escape((ts or '')[:19])}</td>"
                f"<td>{safe_ip}</td>"
                f"<td>{html.escape(username or '')}</td>"
                f"<td>{html.escape(password or '')}</td>"
                f"<td>{html.escape(ua_short)}</td>"
                f"<td>{html.escape(status or '')}</td>"
            )
            attack_rows += (
                f"<td><form method='POST' action='/admin/block?secret={urllib.parse.quote(ADMIN_SECRET)}' "
                "style='display:inline;'>"
                f"<input type='hidden' name='ip' value='{safe_ip}'>"
                "<button class='btn-block' type='submit'>Заблокировать навсегда</button></form></td></tr>"
            )

        conn.close()

        page = ADMIN_PAGE_TEMPLATE.format(
            admin_secret_url=urllib.parse.quote(ADMIN_SECRET),
            admin_secret_js=html.escape(urllib.parse.quote(ADMIN_SECRET), quote=True),
            total_attacks=total_attacks,
            unique_ips=unique_ips,
            blocked_count=blocked_count,
            top_ips_rows=top_ips_rows,
            blocked_rows=blocked_rows,
            attack_rows=attack_rows,
        )
        self.send_html_response(200, page)

    def do_POST(self):
        ip = self.get_client_ip()
        user_agent = self.headers.get("User-Agent", "Unknown")[:300]
        parsed_url = urllib.parse.urlparse(self.path)
        path = parsed_url.path

        if path in ("/admin/block", "/admin/unblock"):
            if not self.require_admin(parsed_url.query):
                return

            content_length = int(self.headers.get("Content-Length", 0))
            post_data = self.rfile.read(content_length).decode("utf-8")
            params = urllib.parse.parse_qs(post_data)

            if path == "/admin/block":
                ip_to_block = params.get("ip", [""])[0]
                if ip_to_block:
                    block_ip_permanently(ip_to_block, "Manual block from admin panel")
            else:
                ip_to_unblock = params.get("ip", [""])[0]
                if ip_to_unblock:
                    unblock_ip(ip_to_unblock)

            self.send_response(302)
            self.send_header("Location", self.admin_url())
            self.end_headers()
            return

        if is_ip_blocked(ip) or is_temporarily_blocked(ip):
            self.send_html_response(403, "<h1>Доступ запрещён</h1><p>Ваш IP заблокирован.</p>")
            return

        if path == "/auth":
            content_length = int(self.headers.get("Content-Length", 0))
            post_data = self.rfile.read(content_length).decode("utf-8")
            params = urllib.parse.parse_qs(post_data)
            login = params.get("login", [""])[0]
            password = params.get("password", [""])[0]

            if is_suspicious(login) or is_suspicious(password):
                attack_type = detect_attack_type(f"{login} {password}")
                save_attack(ip, login, password, user_agent, attack_type)
                block_ip_permanently(ip, "Detected SQL injection, XSS, or similar suspicious payload")
                self.send_html_response(
                    403,
                    "<h1>Доступ запрещён</h1><p>Обнаружена подозрительная активность.</p>",
                )
                return

            valid_creds = {
                "admin": "Qwerty123",
                "operator": "Operator2024",
                "security": "SecurePass456",
            }

            if login in valid_creds and valid_creds[login] == password:
                save_attack(ip, login, password, user_agent, "SUCCESS_LOGIN")
                failed_attempts[ip] = []
                self.send_response(302)
                self.send_header("Location", "https://www.gov.kg")
                self.end_headers()
            else:
                save_attack(ip, login, password, user_agent, "FAILED_LOGIN")
                add_failed_attempt(ip)
                if is_temporarily_blocked(ip):
                    save_attack(ip, login, password, user_agent, "TEMPORARY_BLOCKED")
                time.sleep(2)
                self.send_html_response(401, ERROR_PAGE)
            return

        self.send_html_response(404, "<h1>404 Not Found</h1>")


# ------------------------------------------------------------
# 9. Server startup
# ------------------------------------------------------------
def run_server():
    server = HTTPServer(("0.0.0.0", PORT), HoneypotHandler)

    backup_thread = threading.Thread(target=backup_scheduler, daemon=True)
    backup_thread.start()

    print(f"[+] HTTP server started on 0.0.0.0:{PORT}")
    print("[+] Render provides public HTTPS through its proxy; local SSL is disabled.")
    print(f"[*] Admin panel: /admin?secret={ADMIN_SECRET}")
    print("[*] Honeypot credentials:")
    print("    -> admin / Qwerty123")
    print("    -> operator / Operator2024")
    print("    -> security / SecurePass456")

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[!] Stopping server...")
        server.shutdown()


create_backup()

if __name__ == "__main__":
    run_server()
