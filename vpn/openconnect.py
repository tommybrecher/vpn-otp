import logging
import os
import signal
import sys
from typing import TextIO

import pexpect

from vpn.credentials import Credentials

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)


class BackendException(Exception):
    def __init__(self, message):
        self.message = message


class CensorOutput:
    def __init__(self, process, logfile):
        self.process = process
        self.logfile = logfile

    def __enter__(self):
        if self.process is not None:
            logger.info(" **************")
            self.process.logfile = None
        return self

    def __exit__(self, *_):
        if self.process is not None:
            self.process.logfile = self.logfile
        return self


class OpenConnect:
    backend: str = "openconnect"
    failure_check: str = r"(error|invalid|failed|kill)/ig"

    def __init__(self, credentials: Credentials, logfile: TextIO | None) -> None:
        self.credentials: Credentials = credentials
        self.args: list[str] = []
        self.logfile = logfile
        self.process: pexpect.spawn | None = None

    def set_arguments(self, args: list[str]):
        self.args = args

    def spawn(self) -> pexpect.spawn:
        logger.debug(f"Starting {self.backend} with args: {' '.join(self.args)}")
        self.process = pexpect.spawn(
            command=self.backend,
            args=self.args,
            encoding="utf-8",
            codec_errors="ignore",
            logfile=self.logfile,
            timeout=None,  # type: ignore
            echo=False,
        )
        return self.process

    def connect(self):
        if self.process is None:
            raise BackendException("OpenConnect failed to connect or was not spawned")

        self.process.expect("Password:")
        with CensorOutput(self.process, self.logfile):
            self.process.sendline(f"{self.credentials.password}{self.credentials.otptoken.now()}")

    def run_cleanup(self):
        for dirpath, _, filenames in os.walk("/etc/resolver/"):
            for filename in filenames:
                file_path = os.path.join(dirpath, filename)
                logger.info(f"Removing {file_path}..")
                os.remove(os.path.join(dirpath, filename))

    def spawn_and_connect(self) -> pexpect.spawn:
        process = self.spawn()
        self.connect()
        return process

    def connect_with_retries(self):
        max_attempts = 3

        existing_connections = r"\[(?:[^|]{8}\|){0,}([\d\w]*)\]"
        expecting = [self.failure_check, existing_connections, pexpect.EOF]

        for attempt in range(1, max_attempts + 1):
            process = self.spawn_and_connect()
            try:
                while True:
                    # Output that is not a newline, whoops vpn is chatty and prints a lot of stuff
                    if (index := process.expect(expecting, timeout=None)) == 0:  # type: ignore
                        if (match := process.match) is not None:
                            if (output := match.group(0)) != "\r\n":
                                logger.info(f"{output}")
                                break
                    # Output that matches pattern for too many connections, try to kill the first one
                    elif index == 1:
                        if (match := process.match) is not None:
                            if output := match.group(1):
                                process.sendline(output)
                    # EOF, connection closed
                    elif index == 2:
                        logger.warning("Invalid username or password, retrying")
                        break

                    if attempt == max_attempts:
                        logger.info(f"Maximum attempts exceeded, sending SIGINT. {max_attempts=}")
                        process.kill(signal.SIGINT)
                        sys.exit()

                    logger.info(f"VPN disconnected, reconnecting... {attempt=}")
            except KeyboardInterrupt:
                if process:
                    logger.info("Received Ctrl+C sending SIGINT")
                    process.kill(signal.SIGINT)
                    self.run_cleanup()
                    sys.exit()
