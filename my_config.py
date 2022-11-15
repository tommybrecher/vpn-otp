from configparser import ConfigParser
from dataclasses import dataclass, field
from logging import getLogger

from vpn.config import create_config_if_missing_and_read
from vpn.credentials import Credentials

logger = getLogger(__name__)

@dataclass
class ConfigHelper:
    username: str
    password: str = field(init=False)
    psk: str = field(init=False)
    credentials: Credentials = field(init=False)
    configs: ConfigParser = field(init=False)

    def __post_init__(self):
        self.credentials = Credentials(username=self.username)
        self.credentials.get_or_set_and_store_password()
        self.credentials.get_or_set_and_store_token()
        self.configs = create_config_if_missing_and_read()

    def get_args(self) -> list[str]:
        return [i.strip() for i in self.configs["pulse"]["args"].split()]

    def get_domains(self) -> str:
        return ",".join([i.strip() for i in self.configs["pulse"]["domains"].split()])

    def get_routes_config(self) -> str:
        return " ".join([i.strip() for i in self.configs["pulse"]["routes"].split()])
