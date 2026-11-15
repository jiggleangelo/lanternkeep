from typing import Protocol


class StoreAPI(Protocol):
    def submit(self, app_id: str, manifest: dict) -> tuple[bool, str]: ...


class BuildRunner(Protocol):
    def run(self, manifest: dict) -> tuple[bool, str]: ...


class PatchAgent(Protocol):
    def propose(self, manifest: dict, findings: list, platform: str) -> list: ...


class AdvisoryDB(Protocol):
    def lookup(self, dep: str, version: str) -> list[dict]: ...


class Vault(Protocol):
    def put(self, secret: str) -> str: ...


class Clock(Protocol):
    def today(self): ...
