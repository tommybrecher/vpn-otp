#!/usr/bin/env python3.11
# -*- coding: utf-8 -*-
import logging
import sys

import click
from my_config import ConfigHelper
from vpn.openconnect import OpenConnect
import os

logger = logging.getLogger()
logger.setLevel(logging.DEBUG)
logger.addHandler(logging.StreamHandler())


def environment_get(key: str) -> str:
    value = ""
    try:
        value = os.environ[key]
    except KeyError as err:
        logger.error(f"Failed getting {key=} from environment")
        logger.exception(err)
    return value


def get_username() -> str:
    if (user := environment_get("USER")) and user != "root":
        return user
    return environment_get("SUDO_USER")


@click.command()
@click.option("--debug", is_flag=True, default=False, help="Prints output to stdout")
def main(debug: bool):
    username = get_username()

    helper = ConfigHelper(username=username)

    subnets = helper.get_routes_config()
    domains = helper.get_domains()
    run_args = helper.get_args() + [f"-s /usr/local/bin/vpn-slice {subnets} --domains-vpn-dns={domains}"]

    # initialize the backend
    vpn = OpenConnect(credentials=helper.credentials, logfile=sys.stdout if debug else None)
    vpn.set_arguments(run_args)
    vpn.connect_with_retries()


if __name__ == "__main__":
    main()  # pylint: disable=no-value-for-parameter
