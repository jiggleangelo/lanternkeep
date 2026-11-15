from steward.config import Config
from steward.web import make_server


def main():
    config = Config.from_env()
    server = make_server(config.host, config.port, config)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
