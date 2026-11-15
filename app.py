import ipaddress
import logging
import os
import threading
from urllib.parse import urlsplit

from lanternkeep.store import WorkspaceStore
from lanternkeep.web import make_server


def build_server(port=None, clock=None):
    host = os.environ.get("APP_HOST", "127.0.0.1")
    listen_port = int(port if port is not None else os.environ.get("PORT", "8080"))
    base = os.environ.get("PUBLIC_BASE_URL", "https://app-lanternkeep.manykiln.com").rstrip("/")
    parsed = urlsplit(base)
    if (parsed.scheme not in ("http", "https") or not parsed.hostname
            or parsed.username is not None or parsed.password is not None
            or parsed.query or parsed.fragment or parsed.path not in ("", "/")):
        raise ValueError("PUBLIC_BASE_URL must be an HTTP(S) origin")
    data_dir = os.environ.get("DATA_DIR")
    if not data_dir:
        raise ValueError("DATA_DIR is required")
    proxies = tuple(ipaddress.ip_network(item.strip()) for item in
                    os.environ.get("APP_TRUSTED_PROXIES", "").split(",") if item.strip())
    if not proxies:
        logging.getLogger("lanternkeep").warning(
            "APP_TRUSTED_PROXIES is unset: creation limits use the socket peer. "
            "Behind a reverse proxy, all users share its 60/hour client limit. "
            "Configure only your actual trusted proxy addresses. The global "
            "600/hour creation limit applies across all clients.")
    store = WorkspaceStore(data_dir, float(os.environ.get("APP_DATA_CAP_MB", "200")), clock=clock)
    store.sweep()
    return make_server(host, listen_port, base, store,
                       https_terminated=os.environ.get("APP_HTTPS_TERMINATED", "false").lower() == "true",
                       trusted_proxies=proxies)


def start_sweeper(store):
    def run():
        while not store.stop_event.wait(86400):
            store.sweep()
    thread = threading.Thread(target=run, name="lanternkeep-sweeper", daemon=True)
    thread.start()
    return thread


def main():
    server = build_server()
    start_sweeper(server.store)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.store.stop_event.set()
        server.server_close()


if __name__ == "__main__":
    main()
