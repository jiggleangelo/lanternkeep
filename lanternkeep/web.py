import html
import io
import ipaddress
import json
import socket
import sys
import threading
import time
from datetime import date, datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, quote, urlsplit

from .budget import FIELDS, calculate
from .checks import CATEGORIES, DATA_SAFETY_SCOPE, run_checks
from .multipart import FileTooLarge, parse_form
from .parsers import ParseError, parse_all, redact
from .policy import POLICY
from .sample import ANSWERS, BUDGET, GRADLE, MANIFEST, SAMPLE
from .store import StoreError
from .throttle import MissingLinkLimiter

MAX_BODY = 1024 * 1024
MAX_FILE = 200 * 1024
MAX_FORM_PARTS = 100
REQUEST_TIMEOUT = 10
DOCUMENTS = {"gradle": "App build.gradle or build.gradle.kts", "root_gradle": "Optional root Gradle file",
             "manifest": "AndroidManifest.xml", "plist": "Info.plist", "dependencies": "Dependency list",
             "catalog": "Optional libs.versions.toml"}
ANSWER_NAMES = ("policy_contact", "hosting_region", "transfer_safeguard", "licence", "signing_key", "source_held",
                "account_verified", "transfer_checked", "privacy_manifest", "privacy_updated", "required_target_override")
NOTICE = "Operated by AI agents. Early version: keep your own copy of anything important. Do not enter other people's personal data, user databases, signing keys or keystores, passwords or API secrets. Nothing is charged."
STYLE = "body{font:16px system-ui;max-width:1050px;margin:auto;padding:20px;color:#172033}.notice{background:#fff4c2;border:2px solid #806000;padding:12px}.card{border:1px solid #ccd3df;border-radius:8px;padding:14px;margin:12px 0}.blocker{border-left:6px solid #a00}.high{border-left:6px solid #b66a00}.info{border-left:6px solid #357}label{display:block;margin:8px 0}textarea{width:100%;min-height:90px}input,select,textarea{box-sizing:border-box;padding:7px}button{background:#155eef;color:white;border:0;border-radius:5px;padding:9px 13px}pre{white-space:pre-wrap;background:#f3f5f8;padding:10px;overflow:auto}.warn{color:#900;font-weight:bold}"


def esc(value):
    return html.escape(str(value), quote=True)


def utc_today():
    return datetime.now(timezone.utc).date()


def client_ip(peer, forwarded, trusted_proxies):
    address = ipaddress.ip_address(peer)
    trusted = lambda value: any(value in network for network in trusted_proxies)
    if not trusted(address) or not forwarded:
        return str(address)
    try:
        chain = [ipaddress.ip_address(part.strip()) for part in forwarded.split(",")]
    except ValueError:
        return str(address)
    for candidate in reversed(chain):
        if not trusted(address):
            break
        address = candidate
    return str(address)


class DeadlineReader(io.RawIOBase):
    """Every underlying recv shares one monotonic request deadline."""
    def __init__(self, connection, deadline):
        super().__init__()
        self.connection = connection
        self.deadline = deadline

    def readable(self):
        return True

    def readinto(self, buffer):
        remaining = self.deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError("Request read deadline exceeded")
        self.connection.settimeout(remaining)
        return self.connection.recv_into(buffer)


class BoundedServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, address, handler):
        self.slots = threading.BoundedSemaphore(32)
        self.missing_links = MissingLinkLimiter()
        super().__init__(address, handler)

    def get_request(self):
        request, address = super().get_request()
        request.settimeout(REQUEST_TIMEOUT)
        return request, address

    def process_request(self, request, address):
        if not self.slots.acquire(False):
            try:
                request.sendall(b"HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
            except OSError:
                pass
            finally:
                self.shutdown_request(request)
            return
        try:
            super().process_request(request, address)
        except Exception:
            self.slots.release()
            raise

    def process_request_thread(self, request, address):
        try:
            super().process_request_thread(request, address)
        finally:
            self.slots.release()


def make_server(host, port, base_url, store, https_terminated=False, trusted_proxies=()):
    origin = base_url.rstrip("/")
    public_host = urlsplit(origin).hostname.lower()

    class Handler(BaseHTTPRequestHandler):
        server_version = "Lanternkeep"

        def setup(self):
            self.read_deadline = time.monotonic() + REQUEST_TIMEOUT
            super().setup()
            self.rfile.close()
            self.rfile = io.BufferedReader(DeadlineReader(self.connection, self.read_deadline))

        def end_headers(self):
            # Reads keep their absolute deadline. Responses get a fresh write
            # timeout, including redirects, exports and early error responses.
            self.connection.settimeout(REQUEST_TIMEOUT)
            super().end_headers()

        def log_message(self, *args):
            pass

        def do_GET(self):
            self.dispatch("GET")

        def do_POST(self):
            self.dispatch("POST")

        def dispatch(self, method):
            path = urlsplit(self.path).path
            form = None
            capability = path.startswith(("/w/", "/s/"))
            peer = None
            try:
                if path == "/healthz":
                    return self.raw(200, b"ok", "text/plain; charset=utf-8")
                if not self.valid_host():
                    return self.page(421, "Misdirected Request", "Host does not match PUBLIC_BASE_URL.")
                if method == "POST" and not self.valid_origin():
                    return self.page(403, "Forbidden", "POST requires a same-origin Origin or Referer. Multipart requires Origin.")
                if capability:
                    peer = client_ip(self.client_address[0], self.headers.get("X-Forwarded-For"), trusted_proxies)
                    if self.server.missing_links.blocked(peer):
                        self.close_connection = True
                        return self.page(429, "Too many missing links", "Please wait a minute before trying workspace or share links again.")
                form = self.form() if method == "POST" else None
                if method == "POST" and form is None:
                    return
                bits = [part for part in path.split("/") if part]
                if path == "/" and method == "GET":
                    return self.home()
                if path in ("/start", "/sample") and method == "POST":
                    return self.create(path == "/sample")
                if len(bits) == 2 and bits[0] == "s" and method == "GET":
                    return self.share_page(bits[1])
                if len(bits) >= 2 and bits[0] == "w":
                    token = bits[1]
                    store.read(token, touch=False)
                    if len(bits) == 2 and method == "GET":
                        return self.dashboard(token)
                    if len(bits) == 3:
                        action = bits[2]
                        if method == "GET" and action in ("report", "export"):
                            return getattr(self, action)(token)
                        if method == "GET" and action == "delete":
                            return self.confirm_delete(token)
                        if method == "POST" and action in ("inputs", "budget", "log"):
                            return getattr(self, action)(token, form)
                        if method == "POST" and action == "share":
                            return self.share_on(token)
                        if method == "POST" and action == "delete":
                            store.delete(token)
                            return self.page(200, "Deleted", "Workspace deleted. Its files cannot be recovered.")
                    if len(bits) == 4 and bits[2:] == ["share", "off"] and method == "POST":
                        store.share_off(token)
                        return self.redirect("/w/" + token)
                    if len(bits) == 5 and bits[2] == "findings" and bits[4] in ("review", "reopen") and method == "POST":
                        return self.review(token, bits[3], bits[4], form)
                if peer is not None:
                    self.server.missing_links.record(peer)
                return self.page(404, "Not found", "That route does not exist.")
            except KeyError:
                if peer is not None:
                    self.server.missing_links.record(peer)
                return self.page(404, "Not found", "Workspace or share link not found.")
            except (ParseError, StoreError, ValueError) as exc:
                status = 507 if isinstance(exc, StoreError) else 400
                if form is not None and path.startswith("/w/"):
                    return self.retry(path, form, str(exc), status)
                return self.page(status, "Could not save", esc(exc))
            except (socket.timeout, TimeoutError):
                self.close_connection = True
                return self.page(408, "Request timeout", "The request read deadline was exceeded.")
            except (BrokenPipeError, ConnectionResetError):
                return
            except Exception as exc:
                print("Lanternkeep %s route=%s" % (type(exc).__name__, "/w/*" if path.startswith("/w/") else "/s/*" if path.startswith("/s/") else "other"), file=sys.stderr)
                return self.page(500, "Server error", "The action could not be completed.")

        def valid_host(self):
            try:
                supplied = urlsplit("//" + self.headers.get("Host", "")).hostname
                return bool(supplied) and supplied.lower() == public_host
            except ValueError:
                return False

        def valid_origin(self):
            supplied = self.headers.get("Origin")
            if supplied is not None:
                return supplied.rstrip("/") == origin
            if self.headers.get("Content-Type", "").lower().startswith("multipart/form-data"):
                return False
            referer = urlsplit(self.headers.get("Referer", ""))
            return "%s://%s" % (referer.scheme, referer.netloc) == origin

        def form(self):
            raw = self.headers.get("Content-Length")
            if raw is None:
                self.page(411, "Length required", "Content-Length is required.")
                return None
            try:
                length = int(raw)
            except ValueError:
                self.page(400, "Bad request", "Invalid Content-Length.")
                return None
            if length < 0 or length > MAX_BODY:
                self.close_connection = True
                self.page(413, "Payload too large", "Requests are limited to 1 MB.")
                return None
            if time.monotonic() >= self.read_deadline:
                raise TimeoutError()
            body = self.rfile.read(length)
            if time.monotonic() >= self.read_deadline:
                raise TimeoutError()
            if len(body) != length:
                raise ValueError("Incomplete request body")
            content_type = self.headers.get("Content-Type", "")
            if content_type.startswith("application/x-www-form-urlencoded"):
                return parse_qs(body.decode("utf-8", "strict"), keep_blank_values=True, max_num_fields=MAX_FORM_PARTS)
            if content_type.startswith("multipart/form-data"):
                try:
                    return parse_form(content_type, body, MAX_FORM_PARTS, MAX_FILE)
                except FileTooLarge:
                    self.page(413, "File too large", "Each uploaded or pasted file is limited to 200 KB.")
                    return None
            self.page(415, "Unsupported media type", "Use a browser form.")
            return None

        def one(self, form, name, default=""):
            return form.get(name, [default])[0]

        def document_values(self, form):
            result = {}
            for name in DOCUMENTS:
                for value in form.get(name, []) + form.get(name + "_file", []):
                    if len(value.encode()) > MAX_FILE:
                        raise ValueError("Each file is limited to 200 KB")
                result[name] = self.one(form, name + "_file") or self.one(form, name)
            return result

        def retry(self, path, form, error, status):
            if path.endswith("/inputs"):
                return self.dashboard(path.split("/")[2], form=form, error=error, status=status)
            body = "<h1>Could not save</h1><p class=warn>%s</p><p>Correct the fields and retry. Nothing from this failed submission was saved.</p><form method=post action='%s'>" % (esc(error), esc(path))
            if path.endswith("/review"):
                for name in ("read_diff", "tested", "checked_source"):
                    body += "<label><input type=checkbox name='%s'%s> %s</label>" % (name, " checked" if self.one(form, name) else "", esc(name.replace("_", " ")))
            else:
                allowed = FIELDS if path.endswith("/budget") else ("kind", "version", "date", "note", "finding")
                for name in allowed:
                    for value in form.get(name, [""]):
                        body += "<label>%s<textarea name='%s'>%s</textarea></label>" % (esc(name), name, esc(redact(value)[0]))
            return self.page(status, "Could not save", body + "<button>Retry</button></form>")

        def create(self, sample):
            peer = client_ip(self.client_address[0], self.headers.get("X-Forwarded-For"), trusted_proxies)
            token = store.create(SAMPLE if sample else None, client_id=peer)
            if sample:
                facts = parse_all({"gradle": [GRADLE], "manifest": MANIFEST})
                def seed(state):
                    state.update(inputs_facts=facts, answers=dict(ANSWERS), findings=run_checks(facts, ANSWERS, POLICY),
                                 budget=calculate(BUDGET), warning="Made-up example budget")
                store.update(token, seed)
            return self.redirect("/w/" + token)

        def home(self):
            return self.page(200, "lanternkeep", "<h1>lanternkeep</h1><p>Paste an old app's build files, answer a few questions, and get a prioritised handover-readiness report and a shareable maintenance log.</p><p><strong>Rules and templates only. No AI model reads your files.</strong></p><form method=post action='/start'><button>Start a workspace</button></form><form method=post action='/sample'><button>Try with sample data</button></form>")

        def dashboard(self, token, form=None, error="", status=200):
            state = store.read(token)
            answer = state.get("answers", {})
            values = {}
            if form is not None:
                answer = {name: self.one(form, name) for name in ANSWER_NAMES}
                answer.update({name: form.get(name, []) for name in ("data_categories", "privacy_categories")})
                values = {name: redact((self.one(form, name + "_file") or self.one(form, name))[:MAX_FILE])[0] for name in DOCUMENTS}
            base = "/w/" + esc(token)
            body = "<h1>Workspace</h1><p class=warn>Bookmark this link: it is the only key and cannot be recovered.</p>"
            if state.get("sample"):
                body += "<p class=warn>Made-up sample</p>"
            if error:
                body += "<p class=warn>%s</p><p>Correct the form below. This failed submission was not saved; suspected secrets have been removed.</p>" % esc(error)
            if state.get("warning"):
                body += "<p class=warn>%s</p>" % esc(state["warning"])
            counts = {level: sum(f["severity"] == level for f in state.get("findings", [])) for level in ("blocker", "high", "info")}
            body += "<p><a href='%s/report'>Readiness report</a> — blockers %s, high %s, info %s</p>" % (base, counts["blocker"], counts["high"], counts["info"])
            body += "<div class=card><h2>Inputs</h2><p>Full documents are discarded after parsing. Only parsed facts and at most 200 matched lines are stored. Resubmit the files to update your report. Each file is limited to 200 KB and each request to 1 MB. A nonempty upload replaces the corresponding pasted text.</p><form method=post enctype='multipart/form-data' action='%s/inputs'>" % base
            for name, label in DOCUMENTS.items():
                body += "<label>%s<textarea name=%s>%s</textarea></label><label>Upload %s <input type=file name=%s_file></label>" % (esc(label), name, esc(values.get(name, "")), esc(label), name)
            for name, label in (("data_categories", "Store data-safety categories"), ("privacy_categories", "Privacy-policy categories")):
                body += "<h3>%s</h3>" % label
                for category in CATEGORIES:
                    body += "<label><input type=checkbox name='%s' value='%s'%s> %s</label>" % (name, category, " checked" if category in answer.get(name, []) else "", category.replace("_", " "))
            for name, label in (("privacy_updated", "Policy last updated"), ("hosting_region", "Hosting region"), ("required_target_override", "Required target API override")):
                body += "<label>%s <input name='%s' value='%s' maxlength=80></label>" % (label, name, esc(answer.get(name, "")))
            for name, label in (("policy_contact", "Policy shows a contact for data questions"), ("transfer_safeguard", "Transfer safeguard confirmed"), ("signing_key", "Signing key held"), ("source_held", "Source held"), ("account_verified", "Store account verified"), ("transfer_checked", "Transfer eligibility checked"), ("privacy_manifest", "PrivacyInfo.xcprivacy present?"), ("licence", "App licence")):
                options = ("unknown", "proprietary", "open_source") if name == "licence" else ("unknown", "yes", "no")
                body += "<label>%s <select name='%s'>%s</select></label>" % (label, name, "".join("<option value=%s%s>%s</option>" % (item, " selected" if answer.get(name, "unknown") == item else "", item) for item in options))
            body += "<button>Save and build report</button></form></div>"
            budget = state.get("budget") or {}
            result = budget.get("result")
            body += "<div class=card><h2>Keep-alive budget</h2><p>Computed only from your numbers. Fee/split percentage is your assumption. Cash runway divides your cash reserve by monthly net burn, including annual upkeep spread over twelve months. This treats your entered labour cost as a cash expense. Use the same currency for all amounts.</p>"
            if result:
                coverage = result.get("months_of_upkeep_coverage")
                body += "<p>Net annual %.2f; annual upkeep %.2f; months of upkeep coverage %s; break-even monthly revenue %s.</p>" % (result["net_annual"], result["annual_upkeep"], "not applicable (zero upkeep)" if coverage is None else "%.1f" % coverage, "not computable" if result["break_even_monthly_revenue"] is None else "%.2f" % result["break_even_monthly_revenue"])
                if "months_of_runway" not in result:
                    runway = "not assessed; enter your cash reserve"
                elif result["runway_status"] == "no_net_burn":
                    runway = "no finite depletion date at these figures (no net burn)"
                else:
                    runway = "%.1f" % result["months_of_runway"]
                body += "<p>Months of runway: %s.</p>" % esc(runway)
            body += "<p>Upkeep coverage measures how many months of upkeep one year's positive net income could fund; it is separate from cash runway.</p><form method=post action='%s/budget'>" % base
            for name in FIELDS:
                value = budget.get("inputs", {}).get(name)
                body += "<label>%s <input type=number min=0 step=any name='%s' value='%s'></label>" % (esc(name.replace("_", " ")), name, esc("" if value is None else value))
            body += "<button>Calculate</button></form></div><div class=card><h2>Stewardship log</h2><p>The next-check date uses a 90-day Lanternkeep assumption, not a legal deadline. Default entry dates and review dates use UTC; you can enter your own log date.</p>" + self.log_rows(state)
            body += "<form method=post action='%s/log'><select name=kind><option>release</option><option>check</option><option>note</option></select><input name=version maxlength=20 placeholder=Version><input type=date name=date><textarea name=note maxlength=500 placeholder='Your release or maintenance note'></textarea><fieldset><legend>Link findings addressed or checked</legend>" % base
            for item in state.get("findings", []):
                body += "<label><input type=checkbox name=finding value='%s'> %s — %s</label>" % (esc(item["id"]), esc(item["id"]), esc(item["title"]))
            body += "</fieldset><button>Add log entry</button></form>"
            share = store.get_share(token, state)
            if share:
                body += "<p>Current read-only share link: <a href='/s/%s'>%s/s/%s</a></p>" % (esc(share), esc(origin), esc(share))
            elif state.get("share_hash"):
                body += "<p>The legacy share link still works. Its original token cannot be recovered; rotate once to create a redisplayable link.</p>"
            body += "<form method=post action='%s/share'><button>Create or rotate read-only share link</button></form><form method=post action='%s/share/off'><button>Disable share link</button></form></div><p><a href='%s/export'>Export everything stored (JSON)</a></p><div class=card><h2>Delete workspace</h2><p>Deletion is permanent. Export your data first if you need a copy.</p><a href='%s/delete'>Review deletion…</a></div>" % (base, base, base, base)
            return self.page(status, "Workspace", body)

        def confirm_delete(self, token):
            base = "/w/" + esc(token)
            return self.page(200, "Confirm deletion", "<h1>Permanently delete this workspace?</h1><p class=warn>This removes your report, budget and stewardship log, and disables every share link. It cannot be undone.</p><p><a href='%s/export'>Export first</a> · <a href='%s'>Cancel and keep workspace</a></p><form method=post action='%s/delete'><button>Permanently delete this workspace</button></form>" % (base, base, base))

        def inputs(self, token, form):
            values = self.document_values(form)
            gradles = [values["gradle"], values["root_gradle"]] if values["root_gradle"] else [values["gradle"]] if values["gradle"] else []
            facts = parse_all({"gradle": gradles, **{name: values[name] for name in ("manifest", "plist", "dependencies", "catalog")}})
            answers = {name: self.one(form, name) for name in ANSWER_NAMES}
            if any(len(value) > 80 for value in answers.values()):
                raise ValueError("Answers are limited to 80 characters")
            for name in ("data_categories", "privacy_categories"):
                answers[name] = list(dict.fromkeys(form.get(name, [])))
                if any(value not in CATEGORIES for value in answers[name]):
                    raise ValueError("Unknown data category")
            for name in ("policy_contact", "transfer_safeguard", "signing_key", "source_held", "account_verified", "transfer_checked", "privacy_manifest"):
                if answers[name] not in ("", "unknown", "yes", "no"):
                    raise ValueError("Choose yes, no or unknown")
            if answers["licence"] not in ("", "unknown", "proprietary", "open_source"):
                raise ValueError("Unknown licence choice")
            findings = run_checks(facts, answers, POLICY)
            def change(state):
                old = {item["id"]: item for item in state.get("findings", [])}
                state["reviews"] = {item["id"]: state["reviews"][item["id"]] for item in findings
                                    if item["id"] in state.get("reviews", {}) and old.get(item["id"]) == item}
                state.update(inputs_facts=facts, answers=answers, findings=findings,
                             warning="A possible secret was redacted by Lanternkeep before parsing and was not stored. Entire affected lines were skipped; see the report for Gradle line numbers and resubmission instructions." if facts.get("redacted") else None)
                state.pop("input_text", None)
            store.update(token, change)
            return self.redirect("/w/%s/report" % token)

        def report(self, token):
            state = store.read(token)
            body = "<h1>Handover-readiness report</h1><p><strong>Not built or tested by us.</strong> Rules and templates only. No AI model reads your files.</p>"
            body += "<p>%s</p>" % esc(DATA_SAFETY_SCOPE)
            row = POLICY["required_target_sdk"]
            body += "<p>Default target API: %s; policy checked %s, effective %s. %s. %s <a rel=noreferrer href='%s'>Policy source</a>. Your workspace override, if supplied, takes precedence.</p>" % (esc(row["value"]), esc(row["as_of"]), esc(row["effective_from"]), esc(row["scope"]), esc(row["exceptions"]), esc(row["source_url"]))
            for finding in state.get("findings", []):
                fix = finding["fix"]
                fix_html = "".join("<pre>%s</pre>" % esc(item) for item in fix) if isinstance(fix, list) else "<pre>%s</pre>" % esc(fix)
                source = "assumption" if finding["source_url"] == "assumption" else "<a href='%s' rel=noreferrer>source</a>" % esc(finding["source_url"])
                base = "/w/%s/findings/%s" % (esc(token), esc(finding["id"]))
                body += "<div class='card %s'><h2>%s %s: %s</h2><p>%s</p><p>%s; %s</p>%s" % (esc(finding["severity"]), esc(finding["id"]), esc(finding["severity"]), esc(finding["title"]), esc(finding["why"]), esc(finding["assessment"]), source, fix_html)
                if finding["id"] in state.get("reviews", {}):
                    body += "<p>Reviewed and done on %s (UTC for new reviews).</p><form method=post action='%s/reopen'><button>Reopen</button></form>" % (esc(state["reviews"][finding["id"]]), base)
                else:
                    body += "<form method=post action='%s/review'><label><input type=checkbox name=read_diff> I read every diff or action</label><label><input type=checkbox name=tested> I tested or verified everything myself</label><label><input type=checkbox name=checked_source> I checked the source or assumption label</label><button>Reviewed and done</button></form>" % base
                body += "</div>"
            dependencies = list(state.get("inputs_facts", {}).get("dependency_list", {}).get("dependencies", []))
            for gradle in state.get("inputs_facts", {}).get("gradle", []):
                dependencies.extend(gradle.get("dependencies", []))
            if dependencies:
                body += "<h2>Dependency lookups</h2><p>No vulnerability requests were made.</p><ul>"
                for dep in dependencies:
                    body += "<li>%s — <a rel=noreferrer href='https://osv.dev/list?q=%s'>Look up at OSV</a></li>" % (esc(dep["coordinate"]), esc(quote(dep["name"], safe="")))
                body += "</ul>"
            return self.page(200, "Readiness report", body + "<p><a href='/w/%s'>Back to workspace</a></p>" % esc(token))

        def review(self, token, finding_id, action, form):
            def change(state):
                if not any(item["id"] == finding_id for item in state.get("findings", [])):
                    raise ValueError("Finding not found")
                if action == "review":
                    if not all(self.one(form, name) == "on" for name in ("read_diff", "tested", "checked_source")):
                        raise ValueError("All three review boxes are required")
                    state.setdefault("reviews", {})[finding_id] = utc_today().isoformat()
                else:
                    state.setdefault("reviews", {}).pop(finding_id, None)
            store.update(token, change)
            return self.redirect("/w/%s/report" % token)

        def budget(self, token, form):
            result = calculate({name: self.one(form, name) for name in FIELDS})
            store.update(token, lambda state: state.update(budget=result))
            return self.redirect("/w/" + token)

        def log(self, token, form):
            kind = self.one(form, "kind")
            version, note = self.one(form, "version").strip(), self.one(form, "note").strip()
            if kind not in ("release", "check", "note") or len(version) > 20 or len(note) > 500:
                raise ValueError("Invalid log entry")
            entry_date = date.fromisoformat(self.one(form, "date") or utc_today().isoformat())
            requested = list(dict.fromkeys(form.get("finding", [])))
            if len(requested) > 50:
                raise ValueError("Link at most 50 findings")
            def change(state):
                valid = {item["id"] for item in state.get("findings", [])}
                if any(item not in valid for item in requested):
                    raise ValueError("A linked finding does not exist")
                state.setdefault("log", []).append({"kind": kind, "version": version, "date": entry_date.isoformat(),
                    "note": note, "finding_ids": requested, "next_check_due": (entry_date + timedelta(days=90)).isoformat(),
                    "next_check_basis": "Lanternkeep 90-day assumption"})
            store.update(token, change)
            return self.redirect("/w/" + token)

        def log_rows(self, state):
            return "<ul>" + ("".join("<li>%s — %s %s: %s; findings %s; next check %s (90-day assumption)</li>" %
                (esc(entry.get("date", "")), esc(entry.get("kind", "")), esc(entry.get("version", "")), esc(entry.get("note", "")),
                 esc(", ".join(entry.get("finding_ids", [])) or "none"), esc(entry.get("next_check_due", "")))
                for entry in state.get("log", [])) or "<li>No entries yet.</li>") + "</ul>"

        def share_on(self, token):
            share = store.set_share(token)
            return self.page(200, "Share link", "<h1>Read-only share link</h1><p><a href='/s/%s'>%s/s/%s</a></p><p>This link remains available on your workspace dashboard. Rotating it invalidates the previous link.</p><a href='/w/%s'>Back to workspace</a>" % (esc(share), esc(origin), esc(share), esc(token)))

        def share_page(self, share):
            state = store.read_share(share)
            counts = {level: sum(item["severity"] == level and item["id"] not in state.get("reviews", {}) for item in state.get("findings", [])) for level in ("blocker", "high", "info")}
            body = "<h1>Read-only stewardship log</h1><p>Open findings: %s blockers, %s high, %s info.</p>" % (counts["blocker"], counts["high"], counts["info"])
            if state.get("sample"):
                body += "<p>Made-up sample</p>"
            return self.page(200, "Shared stewardship log", body + self.log_rows(state))

        def export(self, token):
            payload = json.dumps(store.read(token), ensure_ascii=False, indent=2).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Disposition", 'attachment; filename="lanternkeep-export.json"')
            self.security()
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

        def redirect(self, location):
            self.send_response(303)
            self.send_header("Location", origin + location)
            self.security()
            self.send_header("Content-Length", "0")
            self.end_headers()

        def security(self):
            self.send_header("Content-Security-Policy", "default-src 'self'; style-src 'self' 'unsafe-inline'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'")
            self.send_header("Referrer-Policy", "same-origin")
            self.send_header("X-Frame-Options", "DENY")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Cache-Control", "no-store")
            if https_terminated:
                self.send_header("Strict-Transport-Security", "max-age=31536000; includeSubDomains")

        def raw(self, status, body, content_type):
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            if status == 429:
                self.send_header("Retry-After", "60")
            self.security()
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def page(self, status, title, body):
            notice = "%s <a href='https://manykiln.com/privacy' rel=noreferrer>Privacy</a>" % esc(NOTICE)
            document = ("<!doctype html><html><head><meta charset=utf-8><meta name=viewport content='width=device-width'><title>%s</title><style>%s</style></head><body><div class=notice>%s</div><nav><a href='/'>Home</a></nav>%s</body></html>" % (esc(title), STYLE, notice, body)).encode()
            self.raw(status, document, "text/html; charset=utf-8")

    server = BoundedServer((host, port), Handler)
    server.store = store
    return server
