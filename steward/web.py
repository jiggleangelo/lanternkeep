import base64
import binascii
import copy
import html
import math
import secrets
import socket
import sys
import threading
import time
from datetime import datetime, timezone
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit
from .fakes import FakeAdvisoryDB, FakeBuildRunner, FakePatchAgent, FakeStore, FixedClock
from .models import AppRecord, Submission
from .offers import calculate
from .pipeline import Pipeline, PipelineError
from .seed import manifest_for_submission, seed_apps
from .triage import triage
from .vault import MemoryVault

BANNER = "Demo operated by AI agents. Made-up data. Do not enter real personal data. Nothing is charged."
STYLE = "body{font:16px system-ui;max-width:1050px;margin:auto;padding:20px;color:#172033}nav a{margin-right:16px}.banner{background:#fff1b8;padding:12px;border:2px solid #8b6508}.card{border:1px solid #ccd3df;border-radius:8px;padding:14px;margin:12px 0}.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(260px,1fr));gap:12px}label{display:block;margin:9px 0}input,select{padding:7px;max-width:95%}button,.button{background:#155eef;color:white;border:0;border-radius:5px;padding:9px 13px;text-decoration:none;display:inline-block}pre{white-space:pre-wrap;background:#f3f5f8;padding:10px}.blocker{color:#a00}.high{color:#9a5900}.info{color:#345}small{color:#596579}"
MAX_BODY = 65536
MAX_FIELDS = 30
MAX_SUBMISSIONS = 20
MAX_APPS = 25
MAX_SESSIONS = 300
MAX_WORKERS = 32
REQUEST_TIMEOUT = 10


def esc(value):
    return html.escape(str(value), quote=True)


class State:
    def __init__(self, config):
        self.config, self.sessions, self.lock = config, {}, threading.Lock()
        self.advisories, self.clock = FakeAdvisoryDB(), FixedClock()

    def session(self, sid=None):
        now = time.monotonic()
        with self.lock:
            expired = [key for key, value in self.sessions.items() if now - value["seen"] > 7200]
            for key in expired:
                self._discard(key)
            if not sid or sid not in self.sessions:
                while len(self.sessions) >= MAX_SESSIONS:
                    oldest = min(self.sessions, key=lambda key: self.sessions[key]["seen"])
                    self._discard(oldest)
                sid = secrets.token_hex(16)
                self.sessions[sid] = {
                    "seen": now,
                    "csrf": secrets.token_hex(16),
                    "apps": None,
                    "submissions": {},
                    "vault": MemoryVault(MAX_SUBMISSIONS),
                    "lock": threading.RLock(),
                }
            self.sessions[sid]["seen"] = now
            return sid, self.sessions[sid]

    def _discard(self, sid):
        session = self.sessions.pop(sid, None)
        if session:
            session["vault"].clear()

    @staticmethod
    def apps(session):
        if session["apps"] is None:
            session["apps"] = copy.deepcopy(seed_apps())
        return session["apps"]

    def reset(self, sid):
        session = self.sessions[sid]
        session["vault"].clear()
        session["apps"] = None
        session["submissions"] = {}
        session["seen"] = time.monotonic()


class BoundedHTTPServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, address, handler, max_workers=MAX_WORKERS, request_timeout=REQUEST_TIMEOUT):
        self.max_workers = max_workers
        self.request_timeout = request_timeout
        self._worker_slots = threading.BoundedSemaphore(max_workers)
        super().__init__(address, handler)

    def get_request(self):
        request, client_address = super().get_request()
        request.settimeout(self.request_timeout)
        return request, client_address

    def process_request(self, request, client_address):
        if not self._worker_slots.acquire(blocking=False):
            try:
                request.sendall(b"HTTP/1.1 503 Service Unavailable\r\nConnection: close\r\nContent-Length: 0\r\n\r\n")
            except OSError:
                pass
            self.shutdown_request(request)
            return
        try:
            super().process_request(request, client_address)
        except Exception:
            self._worker_slots.release()
            raise

    def process_request_thread(self, request, client_address):
        try:
            super().process_request_thread(request, client_address)
        finally:
            self._worker_slots.release()


def make_server(host, port, config):
    state = State(config)

    class Handler(BaseHTTPRequestHandler):
        server_version = "StewardDesk"

        def log_message(self, *args):
            pass

        def do_GET(self):
            self._dispatch("GET")

        def do_POST(self):
            self._dispatch("POST")

        def _dispatch(self, method):
            path = urlsplit(self.path).path
            try:
                if path == "/healthz":
                    return self._raw(200, b"ok", "text/plain; charset=utf-8")
                if not self._valid_host():
                    return self._page(421, "Misdirected Request", "The Host header does not match this demo.")
                if not self._authorized():
                    return self._unauthorized()
                needs_session = method == "POST" or path in ("/intake", "/apps") or path.startswith("/apps/") or path.startswith("/intake/")
                if needs_session:
                    self.sid, self.s = state.session(self._cookie("sid"))
                    if method == "POST":
                        form = self._form()
                        if form is None:
                            return
                        supplied = form.get("csrf", [""])[0]
                        if not secrets.compare_digest(supplied, self.s["csrf"]):
                            return self._page(403, "Forbidden", "Invalid CSRF token.")
                        self.form = form
                    with self.s["lock"]:
                        return self._route(method, path)
                return self._route(method, path)
            except (TimeoutError, socket.timeout):
                return self._page(408, "Request timeout", "The request took too long.")
            except (BrokenPipeError, ConnectionResetError):
                return
            except Exception as exc:
                print(f"StewardDesk {type(exc).__name__} route={path}", file=sys.stderr)
                return self._page(500, "Server error", "The demo could not complete that action.")

        def _route(self, method, path):
            if method == "GET" and path == "/":
                return self._home()
            if method == "GET" and path == "/intake":
                return self._intake("sample=1" in self.path)
            if method == "POST" and path == "/intake":
                return self._create_submission()
            if method == "GET" and path == "/apps":
                return self._apps()
            if method == "POST" and path == "/reset":
                state.reset(self.sid)
                return self._redirect("/")
            bits = [part for part in path.split("/") if part]
            if len(bits) == 2 and bits[0] == "intake" and method == "GET":
                return self._submission(bits[1])
            if len(bits) == 3 and bits[0] == "intake" and bits[2] == "accept" and method == "POST":
                return self._accept(bits[1])
            if len(bits) >= 2 and bits[0] == "apps":
                app = state.apps(self.s).get(bits[1])
                if not app:
                    return self._page(404, "Not found", "App not found.")
                if len(bits) == 2 and method == "GET":
                    return self._app(app)
                if len(bits) == 3 and bits[2] == "log" and method == "GET":
                    return self._log(app)
                if len(bits) == 3 and method == "POST" and bits[2] in ("scan", "propose", "release"):
                    return self._action(app, bits[2])
                if len(bits) == 5 and bits[2] == "patches" and method == "POST" and bits[4] in ("approve", "reject"):
                    return self._review(app, bits[3], bits[4])
            known = path in ("/", "/intake", "/apps", "/reset") or path.startswith("/apps/") or path.startswith("/intake/")
            return self._page(405 if known else 404, "Method not allowed" if known else "Not found", "That route is unavailable.")

        def _authorized(self):
            expected = state.config.access_token
            if not expected:
                return True
            header = self.headers.get("Authorization", "")
            if not header.startswith("Basic "):
                return False
            try:
                decoded = base64.b64decode(header[6:], validate=True).decode("utf-8")
                username, password = decoded.split(":", 1)
            except (binascii.Error, UnicodeDecodeError, ValueError):
                return False
            return secrets.compare_digest(username, "steward") and secrets.compare_digest(password, expected)

        def _unauthorized(self):
            body = b"Authentication required."
            self.send_response(401)
            self.send_header("WWW-Authenticate", 'Basic realm="Steward Desk"')
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self._security_headers()
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def _pipeline(self):
            store = FakeStore(state.config.required_target_sdk["android"])
            agent = FakePatchAgent(state.config, state.advisories, state.clock)
            return Pipeline(state.config, state.advisories, state.clock, agent, FakeBuildRunner(), store)

        def _home(self):
            body = "<h1>Steward Desk</h1><p>Qualify a dormant app, compare indicative terms, scan its simulated project, review agent patches and release to a fake store.</p><p><a class=button href='/intake?sample=1'>Acquire or rev-share an app</a> <a href='/apps'>Operator console</a></p><div class=card><h2>Unverified assumptions</h2><p>Acquisition multiples, cost inputs, policy levels and dates, PDPA duties, and store-transfer mechanics are illustrative and must be verified before real use.</p></div>"
            return self._page(200, "Steward Desk", body)

        def _intake(self, sample=False, error="", values=None):
            defaults = {"app_name": "Tidepool Tide Tables", "platform": "android", "store_url": "https://play.example.invalid/tidepool", "mau": "2400", "gross": "180", "fee": "15", "costs": "25", "willing": "either", "source": "on", "key": "on"}
            values = values or (defaults if sample else {})
            value = lambda key: esc(values.get(key, ""))
            selected = lambda key, option: " selected" if values.get(key, "android" if key == "platform" else "either") == option else ""
            checked = lambda key: " checked" if values.get(key) else ""
            body = f"<h1>Seller intake</h1><p><a href='/intake?sample=1'>Load sample app</a></p><p class=blocker>{esc(error)}</p><form method=post action='/intake'><input type=hidden name=csrf value='{self.s['csrf']}'><label>App name <input name=app_name maxlength=100 value='{value('app_name')}' required></label><label>Platform <select name=platform><option{selected('platform','android')}>android</option><option{selected('platform','ios')}>ios</option><option{selected('platform','desktop')}>desktop</option></select></label><label>Store URL <input name=store_url maxlength=500 value='{value('store_url')}' required></label><label>Monthly active users <input name=mau type=number min=0 max=100000000 value='{value('mau')}' required></label><label>Gross revenue/month USD <input name=gross type=number min=0 max=100000000 step=.01 value='{value('gross')}' required></label><label>Store fee % <input name=fee type=number min=0 max=100 step=.01 value='{value('fee') or '15'}'></label><label>Other monthly costs USD <input name=costs type=number min=0 max=100000000 step=.01 value='{value('costs') or '0'}'></label><label><input type=checkbox name=source{checked('source')}> Source available</label><label><input type=checkbox name=key{checked('key')}> Signing key available</label><label>Deal willingness <select name=willing><option value=either{selected('willing','either')}>Either</option><option value=acquire{selected('willing','acquire')}>Acquisition</option><option value=revshare{selected('willing','revshare')}>Rev-share</option><option value=no{selected('willing','no')}>No</option></select></label><label>Contact (optional, maximum 200 characters) <input name=contact maxlength=200 autocomplete=off></label><p><strong>Privacy warning:</strong> this demo stores contact text only in this browser session's bounded in-memory vault. Do not enter real personal data.</p><button>Evaluate</button></form>"
            return self._page(200, "Seller intake", body)

        def _create_submission(self):
            get = lambda key: self.form.get(key, [""])[0]
            safe_values = {key: get(key) for key in ("app_name", "platform", "store_url", "mau", "gross", "fee", "costs", "willing", "source", "key")}
            try:
                app_name, platform, store_url = get("app_name").strip(), get("platform"), get("store_url").strip()
                mau = int(get("mau"))
                gross, fee, costs = float(get("gross")), float(get("fee") or 15), float(get("costs") or 0)
                if not app_name or len(app_name) > 100 or len(store_url) > 500:
                    raise ValueError
                if platform not in ("android", "ios", "desktop") or get("willing") not in ("either", "acquire", "revshare", "no"):
                    raise ValueError
                if not all(math.isfinite(number) for number in (gross, fee, costs)):
                    raise ValueError
                if not (0 <= mau <= 100000000 and 0 <= gross <= 100000000 and 0 <= fee <= 100 and 0 <= costs <= 100000000):
                    raise ValueError
                if len(self.s["submissions"]) >= MAX_SUBMISSIONS:
                    return self._intake(False, "This session has reached its submission limit.", safe_values)
                contact = get("contact").strip()
                if len(contact) > 200:
                    raise ValueError
                contact_token = self.s["vault"].put(contact) if contact else None
                submission_id = "s_" + secrets.token_hex(4)
                submission = Submission(submission_id, app_name, platform, store_url, mau, gross, fee, costs, bool(get("source")), bool(get("key")), get("willing"), contact_token, datetime.now(timezone.utc))
                self.s["submissions"][submission_id] = submission
                return self._redirect("/intake/" + submission_id)
            except (TypeError, ValueError, OverflowError):
                return self._intake(False, "Check the fields and enter bounded numeric values. Contact data was not retained.", safe_values)

        def _submission(self, submission_id):
            submission = self.s["submissions"].get(submission_id)
            if not submission:
                return self._page(404, "Not found", "Submission not found.")
            result, offer = triage(submission), calculate(submission, triage(submission).score, state.config)
            reasons = "".join(f"<li>{esc(reason)}</li>" for reason in result.reasons)
            body = f"<h1>{esc(submission.app_name)}</h1><p>Store URL: {esc(submission.store_url)}</p><div class=card><h2>{'Qualified' if result.qualified else 'Not qualified'} — score {result.score}</h2><ul>{reasons}</ul></div><div class=grid><div class=card><h2>Acquisition</h2><p>Indicative price: {state.config.currency} {offer['price']:.2f}</p><p>Upfront: {offer['upfront']:.2f}; contingent earn-out cap: {offer['earnout']:.2f}</p><small>{esc(offer['earnout_note'])}</small><p>{esc(offer['acquire_verdict'])}</p></div><div class=card><h2>Rev-share</h2><p>Developer annual share: {offer['developer_share']:.2f}</p><p>Steward annual share: {offer['steward_share']:.2f}</p><p>{esc(offer['rev_verdict'])}</p></div></div>"
            if result.qualified:
                body += f"<form method=post action='/intake/{submission.id}/accept'><input type=hidden name=csrf value='{self.s['csrf']}'><label>Deal <select name=deal><option value=revshare>Rev-share</option><option value=acquire>Acquisition</option></select></label><button>Accept indicative deal</button></form>"
            return self._page(200, submission.app_name, body)

        def _accept(self, submission_id):
            submission = self.s["submissions"].get(submission_id)
            if not submission:
                return self._page(404, "Not found", "Submission not found.")
            apps = state.apps(self.s)
            if len(apps) >= MAX_APPS:
                return self._page(409, "Session limit", "This session has reached its app limit.")
            deal = self.form.get("deal", [""])[0]
            if deal not in ("revshare", "acquire"):
                return self._page(400, "Invalid deal", "Choose acquisition or rev-share.")
            app_id = "a_" + secrets.token_hex(4)
            apps[app_id] = AppRecord(app_id, submission.id, submission.app_name, submission.platform, deal, manifest_for_submission(submission, state.config))
            return self._redirect("/apps/" + app_id)

        def _apps(self):
            rows = "".join(f"<li><a href='/apps/{esc(app.id)}'>{esc(app.name)}</a> — {esc(app.platform)} — {esc(app.manifest.get('version'))}</li>" for app in state.apps(self.s).values())
            return self._page(200, "Apps", f"<h1>Operator console</h1><ul>{rows}</ul>")

        def _app(self, app, message=""):
            findings = "".join(f"<li class='{esc(f.severity)}'><strong>{esc(f.rule_id)} {esc(f.severity)}</strong>: {esc(f.title)} — {esc(f.detail)} {'(agent-fixable)' if f.fixable_by_agent else '(human-only)'}</li>" for f in app.findings) or "<li>No scan results yet.</li>"
            patches = []
            for patch in app.patches:
                controls = ""
                if patch.status in ("proposed", "needs_rework"):
                    controls = f"<form method=post action='/apps/{app.id}/patches/{patch.id}/approve'><input type=hidden name=csrf value='{self.s['csrf']}'><label>Reviewer <input name=reviewer maxlength=100></label><label><input type=checkbox name=read_diff> Read diff</label><label><input type=checkbox name=tested_on_device> Tested on device</label><label><input type=checkbox name=policy_reviewed> Policy reviewed</label><button>Approve</button></form><form method=post action='/apps/{app.id}/patches/{patch.id}/reject'><input type=hidden name=csrf value='{self.s['csrf']}'><input name=reviewer maxlength=100 placeholder=Reviewer><input name=reason maxlength=500 placeholder='Reason for rejection'><button>Reject</button></form>"
                patches.append(f"<div class=card><h3>{esc(patch.id)} {esc(patch.summary)}</h3><p>Status: <strong>{esc(patch.status)}</strong>; build: {esc(patch.build)}</p><pre>{esc(patch.diff)}</pre><pre>{esc(patch.build_output)}</pre><p>{esc(patch.rejection_reason)}</p>{controls}</div>")
            body = f"<h1>{esc(app.name)}</h1><p class=blocker>{esc(message)}</p><p>Platform: {esc(app.platform)}; deal: {esc(app.deal)}; version: {esc(app.manifest.get('version'))}</p><form method=post action='/apps/{app.id}/scan'><input type=hidden name=csrf value='{self.s['csrf']}'><button>Run compliance scan</button></form><h2>Findings</h2><ul>{findings}</ul><form method=post action='/apps/{app.id}/propose'><input type=hidden name=csrf value='{self.s['csrf']}'><button>Propose simulated patches</button></form><h2>Patches</h2>{''.join(patches)}<form method=post action='/apps/{app.id}/release'><input type=hidden name=csrf value='{self.s['csrf']}'><button>Release to fake store</button></form><p><a href='/apps/{app.id}/log'>Public stewardship log</a></p>"
            return self._page(200, app.name, body)

        def _action(self, app, action):
            pipeline = self._pipeline()
            try:
                if action == "scan":
                    pipeline.scan(app); message = f"Scan complete: {len(app.findings)} findings."
                elif action == "propose":
                    patches = pipeline.propose(app); message = f"Proposed {len(patches)} simulated patches."
                else:
                    release = pipeline.release(app); message = f"Store result: {release.store_result} — {release.store_reason}"
            except PipelineError as exc:
                message = str(exc)
            return self._app(app, message)

        def _review(self, app, patch_id, action):
            pipeline = self._pipeline()
            get = lambda key: self.form.get(key, [""])[0]
            try:
                if action == "approve":
                    checklist = {key: bool(get(key)) for key in ("read_diff", "tested_on_device", "policy_reviewed")}
                    pipeline.approve(app, patch_id, get("reviewer"), checklist); message = "Patch approved by human reviewer."
                else:
                    pipeline.reject(app, patch_id, get("reviewer"), get("reason")); message = "Patch rejected."
            except PipelineError as exc:
                message = str(exc)
            return self._app(app, message)

        def _log(self, app):
            entries = "".join(f"<tr><td>{esc(entry.date)}</td><td>{esc(entry.action)}</td><td>{esc(entry.version)}</td><td>{entry.open_findings}</td><td>{esc(entry.next_check_due)}</td></tr>" for entry in app.log)
            return self._page(200, "Stewardship log", f"<h1>{esc(app.name)} stewardship log</h1><table><thead><tr><th>Date</th><th>Action</th><th>Version</th><th>Open issues</th><th>Next due</th></tr></thead><tbody>{entries}</tbody></table>")

        def _form(self):
            raw_length = self.headers.get("Content-Length")
            if raw_length is None:
                self._page(411, "Length required", "POST requests require Content-Length."); return None
            try:
                length = int(raw_length)
            except ValueError:
                self._page(400, "Bad request", "Invalid Content-Length."); return None
            if length < 0 or length > MAX_BODY:
                self.close_connection = True
                self._page(413, "Payload too large", "Request bodies are limited to 64 KB."); return None
            if not self.headers.get("Content-Type", "").lower().startswith("application/x-www-form-urlencoded"):
                self._page(415, "Unsupported media type", "Use an HTML form encoding."); return None
            raw = self.rfile.read(length)
            if len(raw) != length:
                self._page(400, "Bad request", "Incomplete request body."); return None
            try:
                return parse_qs(raw.decode("utf-8", "strict"), keep_blank_values=True, max_num_fields=MAX_FIELDS)
            except (UnicodeDecodeError, ValueError):
                self._page(400, "Bad request", "Malformed form or too many fields."); return None

        def _cookie(self, name):
            cookie = SimpleCookie()
            try:
                cookie.load(self.headers.get("Cookie", ""))
            except Exception:
                return None
            return cookie[name].value if name in cookie else None

        def _valid_host(self):
            if not state.config.public_host:
                return True
            try:
                supplied = urlsplit("//" + self.headers.get("Host", "")).hostname
            except ValueError:
                return False
            return bool(supplied) and supplied.lower() == state.config.public_host

        def _security_headers(self):
            self.send_header("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'")
            self.send_header("X-Frame-Options", "DENY")
            self.send_header("Referrer-Policy", "no-referrer")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Cache-Control", "no-store")

        def _raw(self, status, body, content_type):
            self.send_response(status); self.send_header("Content-Type", content_type); self._security_headers(); self.send_header("Content-Length", str(len(body))); self.end_headers(); self.wfile.write(body)

        def _public_markup(self, markup):
            if not state.config.public_base_url:
                return markup
            base = esc(state.config.public_base_url)
            return markup.replace("href='/", f"href='{base}/").replace("action='/", f"action='{base}/")

        def _page(self, status, title, body):
            document = f"<!doctype html><html><head><meta charset=utf-8><meta name=viewport content='width=device-width'><title>{esc(title)}</title><style>{STYLE}</style></head><body><div class=banner>{esc(BANNER)}</div><nav><a href='/'>Home</a><a href='/intake'>Intake</a><a href='/apps'>Apps</a></nav>{body}</body></html>"
            document = self._public_markup(document).encode()
            self.send_response(status); self.send_header("Content-Type", "text/html; charset=utf-8"); self._security_headers()
            if hasattr(self, "sid"):
                cookie = f"sid={self.sid}; Path=/; HttpOnly; SameSite=Lax"
                if state.config.https_terminated or state.config.public_base_url:
                    cookie += "; Secure"
                self.send_header("Set-Cookie", cookie)
            self.send_header("Content-Length", str(len(document))); self.end_headers(); self.wfile.write(document)

        def _redirect(self, location):
            location = state.config.absolute_url(location)
            self.send_response(303); self.send_header("Location", location); self._security_headers()
            if hasattr(self, "sid"):
                cookie = f"sid={self.sid}; Path=/; HttpOnly; SameSite=Lax"
                if state.config.https_terminated or state.config.public_base_url:
                    cookie += "; Secure"
                self.send_header("Set-Cookie", cookie)
            self.send_header("Content-Length", "0"); self.end_headers()

    server = BoundedHTTPServer((host, port), Handler)
    server.state = state
    return server
