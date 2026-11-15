import base64
import hashlib
import hmac
import json
import math
import os
import secrets
import shutil
import threading
import time
from pathlib import Path

MAX_WORKSPACES = 3000
MAX_WORKSPACE_BYTES = 5 * 1024 * 1024
MAX_LOG = 500
MAX_REVIEWS = 200
MAX_CREATES_PER_CLIENT_HOUR = 60
MAX_CREATES_PER_HOUR = 600


class StoreError(RuntimeError):
    pass


class WorkspaceStore:
    def __init__(self, root, cap_mb=200, clock=None):
        if not math.isfinite(cap_mb) or cap_mb < 0:
            raise ValueError("APP_DATA_CAP_MB must be finite and nonnegative")
        self.root = Path(root)
        self.ws_root = self.root / "ws"
        self.share_root = self.root / "share"
        self.meta_path = self.root / "meta.json"
        self.cap_bytes = int(cap_mb * 1024 * 1024)
        self.clock = clock or time.time
        self.guard = threading.RLock()
        self.locks = {}
        self.accessed = {}
        self.stop_event = threading.Event()
        self._rate_secret = secrets.token_bytes(32)
        self._clients = {}
        self._creates = []
        self.root.mkdir(parents=True, exist_ok=True)
        self.ws_root.mkdir(exist_ok=True)
        self.share_root.mkdir(exist_ok=True)
        self._used_bytes = self._measure_total()
        self._remove_file(self.meta_path)
        self._migrate()

    @staticmethod
    def digest(token):
        return hashlib.sha256(token.encode()).hexdigest()

    def _now(self):
        return float(self.clock())

    def _measure_total(self):
        total = 0
        for base, _, files in os.walk(self.root):
            for name in files:
                try:
                    total += os.path.getsize(os.path.join(base, name))
                except FileNotFoundError:
                    pass
        return total

    def _recalculate_used(self):
        with self.guard:
            self._used_bytes = self._measure_total()

    def _atomic_payload(self, path, payload):
        path = Path(path)
        with self.guard:
            old_size = path.stat().st_size if path.exists() else 0
            projected = self._used_bytes - old_size + len(payload)
            if projected > self.cap_bytes and len(payload) > old_size:
                raise StoreError("The app data cap has been reached; no write was made")
            tmp = path.with_name(".tmp-" + secrets.token_hex(8))
            try:
                with open(tmp, "xb") as handle:
                    handle.write(payload)
                    handle.flush()
                    os.fsync(handle.fileno())
                os.replace(tmp, path)
                self._used_bytes = projected
            finally:
                tmp.unlink(missing_ok=True)

    def _atomic(self, path, value):
        self._atomic_payload(path, json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode())

    def _remove_file(self, path):
        with self.guard:
            path = Path(path)
            try:
                size = path.stat().st_size
                path.unlink()
                self._used_bytes = max(0, self._used_bytes - size)
            except FileNotFoundError:
                pass

    @staticmethod
    def _validate_state(state):
        if not isinstance(state, dict):
            raise ValueError("Workspace state must be an object")
        for field in ("created", "last_seen"):
            value = state.get(field, state.get("created"))
            if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value):
                raise ValueError("Invalid workspace timestamp")
        for field in ("answers", "reviews", "inputs_facts"):
            if field in state and not isinstance(state[field], dict):
                raise ValueError("Invalid workspace mapping")
        for field in ("findings", "log"):
            if field in state and (not isinstance(state[field], list) or any(not isinstance(item, dict) for item in state[field])):
                raise ValueError("Invalid workspace history")
        if state.get("budget") is not None and not isinstance(state["budget"], dict):
            raise ValueError("Invalid workspace budget")

    def _quarantine(self, path):
        # Move the entire directory, preserving evidence without serving it.
        # Quarantined bytes still count toward the data cap. No payload or
        # capability is logged. Recovery requires operator filesystem access.
        quarantine = self.root / "quarantine"
        quarantine.mkdir(mode=0o700, exist_ok=True)
        destination = quarantine / (path.name + "-" + secrets.token_hex(8))
        os.replace(path, destination)
        for pointer in list(self.share_root.iterdir()):
            if pointer.is_file() and pointer.read_bytes().strip() == path.name.encode():
                self._remove_file(pointer)

    def _migrate(self):
        from .budget import calculate
        for path in list(self.ws_root.iterdir()):
            state_path = path / "state.json"
            if not state_path.is_file():
                continue
            try:
                with state_path.open("rb") as handle:
                    payload = handle.read(MAX_WORKSPACE_BYTES + 1)
                if len(payload) > MAX_WORKSPACE_BYTES:
                    raise ValueError("Oversized workspace state")
                state = json.loads(payload)
                self._validate_state(state)
                changed = state.get("schema_version") != 2
                if changed:
                    state.pop("input_text", None)
                    state["inputs_facts"] = {}
                    state["findings"] = []
                    state["reviews"] = {}
                    state["warning"] = "Stored documents and the previous report were removed by a privacy update. Resubmit files to generate a new report."
                    if state.get("budget"):
                        state["budget"] = calculate(state["budget"].get("inputs", {}))
                    state["schema_version"] = 2
            except (ValueError, TypeError, AttributeError, RecursionError, OverflowError):
                self._quarantine(path)
                continue
            if changed:
                self._atomic(state_path, state)
            activity = path / "activity"
            if not activity.exists():
                activity.touch()
                stamp = state.get("last_seen", state.get("created", self._now()))
                os.utime(activity, (stamp, stamp))
            for temporary in path.glob(".tmp-*"):
                self._remove_file(temporary)

    def _resolved_key(self, key):
        path = self.ws_root / key
        with self.guard:
            if not (path / "state.json").is_file():
                raise KeyError("workspace not found")
            lock = self.locks.setdefault(key, threading.RLock())
        return key, path, lock

    def _resolved(self, token):
        return self._resolved_key(self.digest(token))

    def _prune_rates(self):
        cutoff = self._now() - 3600
        self._creates = [stamp for stamp in self._creates if stamp > cutoff]
        self._clients = {key: recent for key, stamps in self._clients.items()
                         if (recent := [stamp for stamp in stamps if stamp > cutoff])}
        if not self._clients:
            self._rate_secret = secrets.token_bytes(32)

    def create(self, sample=None, client_id="unknown"):
        with self.guard:
            self._prune_rates()
            client_key = hmac.new(self._rate_secret, str(client_id or "unknown").encode(), hashlib.sha256).hexdigest()
            recent = self._clients.get(client_key, [])
            if len(recent) >= MAX_CREATES_PER_CLIENT_HOUR:
                raise StoreError("No more than 60 workspaces may be created per client per hour")
            if len(self._creates) >= MAX_CREATES_PER_HOUR:
                raise StoreError("The global workspace creation limit has been reached")
            if sum(path.is_dir() for path in self.ws_root.iterdir()) >= MAX_WORKSPACES:
                raise StoreError("The workspace limit has been reached")
            token = secrets.token_urlsafe(24)
            path = self.ws_root / self.digest(token)
            path.mkdir()
            now = self._now()
            state = {"schema_version": 2, "created": now, "last_seen": now, "written": False,
                     "sample": sample, "inputs_facts": {}, "answers": {}, "findings": [],
                     "reviews": {}, "budget": None, "log": [], "share_hash": None,
                     "share_nonce": None, "warning": None}
            try:
                self._atomic(path / "state.json", state)
                (path / "activity").touch()
                os.utime(path / "activity", (now, now))
            except Exception:
                shutil.rmtree(path, ignore_errors=True)
                self._recalculate_used()
                raise
            self._clients[client_key] = recent + [now]
            self._creates.append(now)
            return token

    def _load(self, key, path):
        try:
            return json.loads((path / "state.json").read_text())
        except FileNotFoundError as exc:
            raise KeyError("workspace not found") from exc

    def _touch(self, path):
        now = self._now()
        os.utime(path / "activity", (now, now))

    def read(self, token, touch=True):
        key, path, lock = self._resolved(token)
        with lock:
            state = self._load(key, path)
            if touch:
                self._touch(path)
            return state

    def _write_resolved(self, key, path, state, mark_written=True):
        if not (path / "state.json").is_file():
            raise KeyError("workspace deleted")
        state.pop("input_text", None)
        if mark_written:
            state["written"] = True
        state["last_seen"] = self._now()
        payload = json.dumps(state, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()
        if len(payload) > MAX_WORKSPACE_BYTES:
            raise StoreError("This workspace exceeds the 5 MB limit")
        self._atomic_payload(path / "state.json", payload)
        self._touch(path)

    def update(self, token, callback):
        key, path, lock = self._resolved(token)
        with lock:
            state = self._load(key, path)
            callback(state)
            if len(state.get("log", [])) > MAX_LOG or len(state.get("reviews", {})) > MAX_REVIEWS:
                raise StoreError("This workspace has reached a history limit")
            self._write_resolved(key, path, state)
            return state

    def _delete_key(self, key, path):
        with self.guard:
            for share_file in list(self.share_root.iterdir()):
                if share_file.is_file() and share_file.read_text().strip() == key:
                    self._remove_file(share_file)
            shutil.rmtree(path)
            self.locks.pop(key, None)
            self.accessed.pop(key, None)
            self._recalculate_used()

    def delete(self, token):
        key, path, lock = self._resolved(token)
        with lock:
            self._load(key, path)
            self._delete_key(key, path)

    @staticmethod
    def _share_token(token, nonce):
        value = hmac.new(token.encode(), ("lanternkeep-share:" + nonce).encode(), hashlib.sha256).digest()
        return base64.urlsafe_b64encode(value).decode().rstrip("=")

    def get_share(self, token, state=None):
        state = state if state is not None else self.read(token, touch=False)
        nonce = state.get("share_nonce")
        if not nonce or not state.get("share_hash"):
            return None
        share = self._share_token(token, nonce)
        return share if self.digest(share) == state["share_hash"] else None

    def set_share(self, token):
        nonce = secrets.token_urlsafe(24)
        new_token = self._share_token(token, nonce)
        share_hash = self.digest(new_token)
        key, path, lock = self._resolved(token)
        pointer = self.share_root / share_hash
        with lock:
            state = self._load(key, path)
            old = state.get("share_hash")
            self._atomic_payload(pointer, key.encode())
            try:
                state["share_hash"] = share_hash
                state["share_nonce"] = nonce
                self._write_resolved(key, path, state)
            except Exception:
                self._remove_file(pointer)
                raise
            if old:
                self._remove_file(self.share_root / old)
        return new_token

    def share_off(self, token):
        key, path, lock = self._resolved(token)
        with lock:
            state = self._load(key, path)
            old = state.get("share_hash")
            state["share_hash"] = None
            state["share_nonce"] = None
            self._write_resolved(key, path, state)
            if old:
                self._remove_file(self.share_root / old)

    def read_share(self, share):
        share_hash = self.digest(share)
        try:
            key = (self.share_root / share_hash).read_text().strip()
        except FileNotFoundError as exc:
            raise KeyError("share not found") from exc
        key, path, lock = self._resolved_key(key)
        with lock:
            state = self._load(key, path)
            if state.get("share_hash") != share_hash:
                raise KeyError("share not found")
            self._touch(path)
            return state

    def sweep(self):
        now = self._now()
        with self.guard:
            self._prune_rates()
        for path in list(self.ws_root.iterdir()):
            try:
                key, path, lock = self._resolved_key(path.name)
                with lock:
                    state = self._load(key, path)
                    activity = (path / "activity").stat().st_mtime
                    age = now - max(state.get("last_seen", state.get("created", now)), activity)
                    never_age = now - state.get("created", now)
                    if age > 90 * 86400 or (not state.get("written") and never_age > 86400):
                        self._delete_key(key, path)
            except (KeyError, FileNotFoundError):
                continue
