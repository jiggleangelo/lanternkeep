"""Bounded in-memory throttling for missing capability links."""
import hashlib
import hmac
import secrets
import threading
import time


class MissingLinkLimiter:
    def __init__(self, limit=30, window=60, max_clients=4096, clock=None):
        self.limit = limit
        self.window = window
        self.max_clients = max_clients
        self.clock = clock or time.monotonic
        self._secret = secrets.token_bytes(32)
        self._entries = {}
        self._lock = threading.Lock()

    def _key(self, client):
        return hmac.new(self._secret, client.encode(), hashlib.sha256).digest()

    def _prune(self, now):
        self._entries = {key: value for key, value in self._entries.items() if value[0] > now}

    def blocked(self, client):
        with self._lock:
            self._prune(self.clock())
            entry = self._entries.get(self._key(client))
            if entry is not None:
                return entry[1] >= self.limit
            # Do not evict active buckets: rotating addresses must not reset
            # the attacker's limits or grow memory without bound.
            return len(self._entries) >= self.max_clients

    def record(self, client):
        with self._lock:
            now = self.clock()
            self._prune(now)
            key = self._key(client)
            entry = self._entries.get(key)
            if entry is None:
                if len(self._entries) < self.max_clients:
                    self._entries[key] = (now + self.window, 1)
            else:
                self._entries[key] = (entry[0], min(self.limit, entry[1] + 1))
