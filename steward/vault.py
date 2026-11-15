import secrets


class MemoryVault:
    def __init__(self, max_entries=25):
        self.__store = {}
        self._max_entries = max_entries

    def put(self, secret: str) -> str:
        if len(self.__store) >= self._max_entries:
            raise ValueError("Contact vault capacity reached.")
        token = "v_" + secrets.token_hex(6)
        self.__store[token] = secret
        return token

    def clear(self):
        self.__store.clear()

    def __len__(self):
        return len(self.__store)
