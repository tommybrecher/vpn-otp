import logging
import sys
from configparser import ConfigParser
from os import makedirs
from os.path import exists, join

import click

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)


def create_config_if_missing_and_read():
    try:
        return read_config()
    except ValueError:
        return generate_config()


def create_cfg_dir(folder=None):
    """
    Ensure config folder exists or creates it
    """
    if folder is None:
        print(f"Invalid config folder {folder}, quitting")
        sys.exit(128)

    if exists(folder):
        return

    logger.info(f"Creating {folder} folder")
    makedirs(folder, exist_ok=True)


def get_config_file_and_parser() -> tuple[str, ConfigParser]:
    cfg_dir = click.get_app_dir("pyotp", force_posix=True)
    config_file = join(cfg_dir, "config")
    parser = ConfigParser()
    create_cfg_dir(folder=cfg_dir)

    return config_file, parser


def generate_config() -> ConfigParser:
    """
    Generating the config file
    """
    config_file, parser = get_config_file_and_parser()
    logger.info(f"Generating configuration file at: {config_file}")

    with open(file=config_file, mode="w", encoding="utf-8") as config_file:
        parser.write(config_file)

    logger.info(msg=f"Successfully Generated config at {config_file}")

    return parser


def read_config() -> ConfigParser:
    """
    Reads the configuration file or create a new one if missing
    """
    config_file, parser = get_config_file_and_parser()

    if not exists(config_file):
        raise ValueError(f"Config file {config_file} not found")

    parser.read(config_file)
    return parser
