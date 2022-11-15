from __future__ import annotations

from dataclasses import dataclass, field
from logging import getLogger
from getpass import getpass

import keyring
from pyotp import TOTP

logger = getLogger(__name__)

_KEYRING_SERVICE_NAME: str = "pyotp"
_KEYRING_TOKEN_SERVICE_NAME: str = "pyotp-totp-token"

@dataclass
class Credentials:
    username: str
    password: str = field(init=False)
    otptoken: TOTP = field(init=False)

    def set_password(self, password: str) -> None:
        self.password = password

    def set_otptoken(self, token: str) -> None:
        self.otptoken = TOTP(token)

    def get_or_set_and_store_password(self) -> str | None:
        if (password := keyring.get_password(service_name=_KEYRING_SERVICE_NAME, username=self.username)):
            self.set_password(password)
            return self.password

        logger.info("Storing password for first time..")
        return self.set_and_store_password(getpass("Enter your password: "))

    def set_and_store_password(self, password: str) -> None:
        keyring.set_password(service_name=_KEYRING_SERVICE_NAME, username=self.username, password=password)
        self.set_password(password)

    def get_or_set_and_store_token(self) -> None:
        if (token := keyring.get_password(service_name=_KEYRING_TOKEN_SERVICE_NAME, username='totp')):
            self.set_otptoken(token)
            return None

        logger.info("Storing TOTP Token for first time..")
        self.store_totp_token(getpass("Enter your TOTP Token: "))

    def store_totp_token(self, token: str) -> None:
        keyring.set_password(service_name=_KEYRING_TOKEN_SERVICE_NAME, username='totp', password=token)
