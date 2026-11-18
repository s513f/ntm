#!/usr/bin/env python3

import hmac
import json
import os
import re
import secrets
import socket
import ssl
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
from collections import deque
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

PORT = 8080
MAX_TEXT = 2000
MAX_NAME = 24
MAX_BODY = 8192
MAX_SESSIONS = 20
MAX_FAILS = 5
LOCK_SECONDS = 60
RATE_COUNT = 8
RATE_WINDOW = 5

messages = []
sessions = {}
fail_log = {}
PASSWORD = ""
lock = threading.Lock()

_CTRL = re.compile(r"[\x00-\x08\x0b-\x1f\x7f-\x9f]")


def clean(s, max_len):
    return _CTRL.sub("", str(s)).strip()[:max_len]


def one_line(s):
    return s.replace("\n", " ")


def add_message(name, sid, text):
    with lock:
        msg = {
            "id": len(messages) + 1,
            "name": name,
            "sid": sid,
            "text": text,
            "time": time.strftime("%H:%M"),
        }
        messages.append(msg)
    return msg


def term_print(line):
    print(f"\n{line}")
    print("ntm> ", end="", flush=True)


class Server(ThreadingHTTPServer):
    daemon_threads = True

    def handle_error(self, request, client_address):
        pass


class Handler(BaseHTTPRequestHandler):
    server_version = "NTM"
    sys_version = ""
    timeout = 15

    def log_message(self, fmt, *args):
        pass

    def _send(self, code, body, ctype="application/json; charset=utf-8"):
        data = body if isinstance(body, bytes) else body.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(data)

    def _json(self, code, obj):
        self._send(code, json.dumps(obj, ensure_ascii=False))

    def _session(self):
        token = self.headers.get("X-Token", "")
        with lock:
            s = sessions.get(token)
        if not s:
            self._json(401, {"error": "unauthorized"})
        return s

    def _read_json(self):
        try:
            length = int(self.headers.get("Content-Length", "0"))
            if length <= 0 or length > MAX_BODY:
                return None
            data = json.loads(self.rfile.read(length).decode("utf-8"))
            return data if isinstance(data, dict) else None
        except Exception:
            return None

    def do_GET(self):
        url = urlparse(self.path)
        if url.path == "/messages":
            if not self._session():
                return
            try:
                after = int(parse_qs(url.query).get("after", ["0"])[0])
            except ValueError:
                after = 0
            with lock:
                new = [m for m in messages if m["id"] > after]
            self._json(200, {"messages": new})
        else:
            self._send(404, "Not found", "text/plain; charset=utf-8")

    def do_POST(self):
        path = urlparse(self.path).path
        if path == "/login":
            self._login()
        elif path == "/send":
            self._post_message()
        else:
            self._send(404, "Not found", "text/plain; charset=utf-8")

    def _login(self):
        ip = self.client_address[0]
        now = time.time()
        with lock:
            count, locked_until = fail_log.get(ip, [0, 0])
        if locked_until > now:
            wait = int(locked_until - now) + 1
            self._json(429, {"error": f"محاولات كثيرة. انتظر {wait} ثانية"})
            return

        data = self._read_json()
        if data is None:
            self._json(400, {"error": "طلب غير صالح"})
            return

        given = str(data.get("password", "")).encode("utf-8")
        if not hmac.compare_digest(given, PASSWORD.encode("utf-8")):
            with lock:
                count += 1
                if count >= MAX_FAILS:
                    fail_log[ip] = [0, now + LOCK_SECONDS]
                else:
                    fail_log[ip] = [count, 0]
            term_print(f"[!] محاولة دخول بكلمة سر خاطئة من {ip}")
            self._json(401, {"error": "كلمة السر غير صحيحة"})
            return

        with lock:
            fail_log.pop(ip, None)
            if len(sessions) >= MAX_SESSIONS:
                full = True
            else:
                full = False
                token = secrets.token_urlsafe(24)
                sid = secrets.token_hex(4)
                name = clean(data.get("name", ""), MAX_NAME) or "ضيف"
                sessions[token] = {"sid": sid, "name": name, "ip": ip, "sent": deque()}
        if full:
            self._json(503, {"error": "الغرفة ممتلئة"})
            return

        add_message("النظام", "system", f"{name} انضم")
        term_print(f"[+] {one_line(name)} انضم من {ip}")
        self._json(200, {"token": token, "sid": sid, "name": name})

    def _post_message(self):
        s = self._session()
        if not s:
            return
        data = self._read_json()
        text = clean(data.get("text", ""), MAX_TEXT) if data else ""
        if not text:
            self._json(400, {"error": "رسالة فارغة"})
            return

        now = time.time()
        with lock:
            sent = s["sent"]
            while sent and now - sent[0] > RATE_WINDOW:
                sent.popleft()
            limited = len(sent) >= RATE_COUNT
            if not limited:
                sent.append(now)
        if limited:
            self._json(429, {"error": "بطيء قليلاً"})
            return

        msg = add_message(s["name"], s["sid"], text)
        term_print(f"[+] {one_line(msg['name'])}: {one_line(msg['text'])}")
        self._json(200, {"ok": True})


def get_local_ips():
    ips = []
    for target in ("10.255.255.255", "192.168.1.1", "8.8.8.8"):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.connect((target, 1))
            ip = s.getsockname()[0]
            if ip and not ip.startswith("127.") and ip not in ips:
                ips.append(ip)
        except Exception:
            pass
        finally:
            s.close()

    for cmd in (["ip", "-4", "addr"], ["ifconfig"]):
        try:
            out = subprocess.run(cmd, capture_output=True, text=True, timeout=3).stdout
        except Exception:
            continue
        for ip in re.findall(r"inet (?:addr:)?(\d+\.\d+\.\d+\.\d+)", out):
            if not ip.startswith("127.") and ip not in ips:
                ips.append(ip)
        if ips:
            break
    return ips


def show_links(scheme="http"):
    ips = get_local_ips()
    if not ips:
        print("[-] لم أستطع معرفة عنوان IP. تأكد أن الهاتفين على نفس الشبكة (Wi-Fi أو Hotspot).")
        return
    print("[*] أعطِ الطرف الآخر أحد هذه العناوين (يكتبه في خيار 2):")
    for ip in ips:
        print(f"    IP: {ip}    المنفذ: {PORT}")


def make_tls_context():
    cert_dir = os.path.join(os.path.expanduser("~"), ".ntm_tls")
    cert = os.path.join(cert_dir, "cert.pem")
    key = os.path.join(cert_dir, "key.pem")
    try:
        if not (os.path.exists(cert) and os.path.exists(key)):
            os.makedirs(cert_dir, mode=0o700, exist_ok=True)
            subprocess.run(
                ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
                 "-keyout", key, "-out", cert, "-days", "365", "-subj", "/CN=ntm"],
                check=True, capture_output=True, timeout=60,
            )
            os.chmod(key, 0o600)
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        ctx.load_cert_chain(cert, key)
        return ctx
    except FileNotFoundError:
        print("[-] openssl غير مثبت. ثبّته بالأمر:  pkg install openssl-tool")
    except Exception as e:
        print(f"[-] تعذر تجهيز HTTPS: {e}")
    return None


def ask(prompt, default=""):
    try:
        value = input(prompt).strip()
    except EOFError:
        raise KeyboardInterrupt
    return value or default


def host_mode():
    global PASSWORD

    pw = ask("كلمة السر (Enter = رقم عشوائي): ")
    if not pw:
        pw = "".join(secrets.choice("0123456789") for _ in range(6))
    PASSWORD = pw

    ctx = None
    if ask("تفعيل HTTPS لتشفير الاتصال؟ (y/N): ").lower() == "y":
        ctx = make_tls_context()
        if ctx is None:
            print("[!] سيعمل الخادم بدون تشفير (HTTP).")
    scheme = "https" if ctx else "http"

    my_name = clean(ask("اسمك (Enter = الخادم): ", "الخادم"), MAX_NAME) or "الخادم"

    try:
        httpd = Server(("0.0.0.0", PORT), Handler)
    except OSError as e:
        print(f"[-] تعذر إنشاء المنفذ {PORT}: {e}")
        return
    if ctx:
        httpd.socket = ctx.wrap_socket(httpd.socket, server_side=True,
                                       do_handshake_on_connect=False)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()

    print(f"\n[*] تم إنشاء المنفذ {PORT} - الخادم يعمل ({scheme.upper()})")
    print(f"[*] كلمة السر: {PASSWORD}")
    show_links(scheme)
    print("[*] الطرف الآخر: يشغّل ntm.py ويختار (2) ثم يكتب IP وكلمة السر.")
    print("\nالأوامر:  نص = إرسال | users = المتصلون | kick اسم = طرد | ntm = الرابط | clear = مسح | close ntm = إغلاق")

    while True:
        try:
            command = input("\nntm> ").strip()
        except (KeyboardInterrupt, EOFError):
            print("\n[*] Exited.")
            break
        if not command:
            continue

        if command == "close ntm":
            print("[*] Closing NTM...")
            break
        elif command == "ntm":
            show_links(scheme)
        elif command == "clear":
            with lock:
                messages.clear()
            print("[*] تم مسح المحادثة.")
        elif command == "users":
            with lock:
                users = [(s["name"], s["ip"]) for s in sessions.values()]
            if not users:
                print("[*] لا أحد متصل.")
            for n, ip in users:
                print(f"    - {one_line(n)}  ({ip})")
        elif command.startswith("kick "):
            target = command[5:].strip()
            with lock:
                gone = [t for t, s in sessions.items() if s["name"] == target]
                for t in gone:
                    del sessions[t]
            if gone:
                add_message("النظام", "system", f"{target} تم طرده")
                print(f"[+] تم طرد {target}")
            else:
                print("[-] لا يوجد مستخدم بهذا الاسم. استخدم users لعرض الأسماء.")
        else:
            add_message(my_name, "server", clean(command, MAX_TEXT))
            print("[+] Sent.")

    httpd.shutdown()
    httpd.server_close()


def client_mode():
    ip = ask("اكتب عنوان IP الخادم (مثل 192.168.1.5): ")
    if not ip:
        print("[-] لم تكتب عنواناً.")
        return
    try:
        port = int(ask(f"المنفذ (Enter = {PORT}): ", str(PORT)))
    except ValueError:
        print("[-] منفذ غير صالح.")
        return
    use_tls = ask("هل الخادم يستخدم HTTPS؟ (y/N): ").lower() == "y"
    my_name = clean(ask("اسمك: ", "ضيف"), MAX_NAME) or "ضيف"
    password = ask("كلمة السر: ")

    scheme = "https" if use_tls else "http"
    base = f"{scheme}://{ip}:{port}"
    tls_ctx = None
    if use_tls:
        tls_ctx = ssl.create_default_context()
        tls_ctx.check_hostname = False
        tls_ctx.verify_mode = ssl.CERT_NONE

    def call(path, payload=None, token=None):
        headers = {}
        data = None
        if payload is not None:
            data = json.dumps(payload).encode("utf-8")
            headers["Content-Type"] = "application/json"
        if token:
            headers["X-Token"] = token
        req = urllib.request.Request(base + path, data=data, headers=headers)
        with urllib.request.urlopen(req, timeout=5, context=tls_ctx) as r:
            return json.loads(r.read().decode("utf-8"))

    try:
        info = call("/login", {"name": my_name, "password": password})
    except urllib.error.HTTPError as e:
        try:
            err = json.loads(e.read().decode("utf-8")).get("error", "")
        except Exception:
            err = ""
        print(f"[-] فشل الدخول: {err or e.code}")
        return
    except Exception as e:
        print(f"[-] تعذر الاتصال بـ {base}: {e}")
        print("    تأكد أن الخادم شغال وأن الهاتفين على نفس الشبكة.")
        return

    token, my_sid = info["token"], info["sid"]
    print(f"\n[*] تم الاتصال بـ {base}")
    print("الأوامر:  نص = إرسال | close ntm = خروج")

    stop = threading.Event()
    state = {"last": 0}

    def poll_loop():
        while not stop.is_set():
            try:
                data = call(f"/messages?after={state['last']}", token=token)
                for m in data["messages"]:
                    state["last"] = m["id"]
                    if m["sid"] == my_sid:
                        continue
                    name, text = one_line(clean(m["name"], MAX_NAME)), one_line(clean(m["text"], MAX_TEXT))
                    if m["sid"] == "system":
                        term_print(f"[*] {text}")
                    else:
                        term_print(f"[+] {name}: {text}")
            except urllib.error.HTTPError as e:
                if e.code == 401:
                    term_print("[!] انتهت الجلسة أو تم طردك.")
                    stop.set()
                    return
            except Exception:
                pass
            stop.wait(1)

    threading.Thread(target=poll_loop, daemon=True).start()

    while not stop.is_set():
        try:
            command = input("\nntm> ").strip()
        except (KeyboardInterrupt, EOFError):
            print("\n[*] Exited.")
            break
        if not command:
            continue
        if command == "close ntm":
            print("[*] Closing NTM...")
            break
        try:
            call("/send", {"text": command[:MAX_TEXT]}, token)
            print("[+] Sent.")
        except urllib.error.HTTPError as e:
            print("[-] تم رفض الرسالة: " + ("أرسل ببطء أكثر" if e.code == 429 else str(e.code)))
        except Exception as e:
            print(f"[-] Failed: {e}")

    stop.set()


def main():
    print("=== NTM (Network Terminal Messenger) ===")
    print("[1] إنشاء منفذ (تشغيل الخادم)")
    print("[2] دخول إلى منفذ (الاتصال بخادم موجود)")
    try:
        choice = ask("اختر 1 أو 2: ")
        if choice == "1":
            host_mode()
        elif choice == "2":
            client_mode()
        else:
            print("[-] اختيار غير صحيح.")
    except KeyboardInterrupt:
        print("\n[*] Exited.")


if __name__ == "__main__":
    main()
