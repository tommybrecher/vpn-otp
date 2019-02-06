#! /usr/bin/env python3
import sys
import pyotp
import base64
import pexpect
import click
from os.path import join, exists
from os import makedirs, urandom
from getpass import getuser, getpass
from configparser import ConfigParser
from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


def create_cfg_dir(folder=None):
    """
    Ensure config folder exists or creates it
    """
    if folder is None:
        print(f'Invalid config folder {folder}, quitting')
        exit(128)

    if exists(folder):
        return

    print(f'Creating {folder} folder')
    makedirs(folder, exist_ok=True)
    return


def generate_config(cfg=None, parser=None):
    """
    Generating the config file
    """
    if not (cfg and parser):
        click_print(msg="An error has occured, quitting", color='blue')
        exit(1)

    click_print(msg=f'Generating configuration file at: {cfg}', color='blue')

    salt = urandom(16)
    fernet = crypt(password, salt)
    token = getpass(prompt='Token: ')
    encrypted = fernet.encrypt(token.encode())

    parser['default'] = dict(
        token=encrypted.hex(),
        salt=salt.hex()
    )

    with open(file=cfg, mode='w') as config_file:
        parser.write(config_file)

    click_print(msg=f'Successfully Generated config at {cfg}', color='blue')
    return


def read_config():
    """
    Reads the configuration file or create a new one if missing 
    """
    cfg_dir = click.get_app_dir('pyotp', force_posix=True)
    cfg = join(cfg_dir, 'config')
    parser = ConfigParser()

    create_cfg_dir(folder=cfg_dir)

    if not exists(cfg):
        generate_config(cfg=cfg, parser=parser)

    parser.read(cfg)
    salt = bytes.fromhex(
        parser['default']['salt']
    )

    token = bytes.fromhex(
        parser['default']['token']
    )

    return salt, token


def crypt(psk, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    key = base64.urlsafe_b64encode(kdf.derive(psk.encode()))
    return Fernet(key)


def click_print(msg=None, color='green'):
    if msg is not None:
        click.echo(click.style(msg, fg=color))


@click.command()
@click.option('--vpn', default='va', type=click.Choice(['va', 'or', 'pulse']))
@click.option('--debug', is_flag=True, help='Prints output to stdout')
@click.option('--creds-only', is_flag=True, help='Only prints credentials')
def main(vpn, debug, creds_only):
    log_level = sys.stdout if debug else None
    cfg_path = click.get_app_dir('pyotp', force_posix=True)
    pulse_url = ''
    commands = {
        'va': f'sudo openvpn {cfg_path}/va.ovpn',
        'or': f'sudo openvpn {cfg_path}/or.ovpn',
        'pulse': f'sudo openconnect --config={cfg_path}/pulse {pulse_url}'
    }

    if creds_only:
        click_print(f'--user={username} --password={password}{otptoken.now()}')
        exit()

    while True:

        process = pexpect.spawn(
            commands[vpn],
            encoding='utf-8',
            logfile=log_level
        )

        if ('va' or 'or') in vpn:
            try:
                click_print(msg='Requesting root access', color='blue')
                process.expect('Enter Auth Username:')
                process.sendline(username)
                process.expect('Enter Auth Password:')
                process.sendline(f'{password}{otptoken.now()}')
                process.expect('Initialization Sequence Completed')
                click_print(msg='Connected')

                while True:
                    process.expect('.+', timeout=None)
                    output = process.match.group(0)

                    if output != '\r\n':
                        click_print(f'openvpn: {output}')
                        break

            except pexpect.EOF:
                click_print(msg='Invalid username or password', color='red')

            except pexpect.TIMEOUT:
                click_print(msg='Cannot connect to OpenVPN!', color='red')

        elif 'pulse' in vpn:
            try:
                click_print(msg='Requesting root access', color='blue')
                process.expect('username:')
                process.sendline(username)
                process.expect('password:')
                process.sendline(f'{password}{otptoken.now()}')

                while True:
                    process.expect(r'(error|invalid|failed)/ig', timeout=None)
                    output = process.match.group(0)

                    if output != '\r\n':
                        click_print(f'openconnect: {output}')
                        break

            except pexpect.EOF:
                click_print(msg='Invalid username or password', color='red')

            except pexpect.TIMEOUT:
                click_print(msg='Connection failed!', color='red')


if __name__ == '__main__':
    # Getting credentials and reading config file
    click_print(msg='Requesting Decryption Key', color='blue')

    username, password = getuser(), getpass()
    salt, token = read_config()

    # Decryption of the key
    fernet = crypt(password, salt)
    token = fernet.decrypt(token).decode()

    # Creating an instance of pyotp
    otptoken = pyotp.totp.TOTP(token)

    # Launching the script
    main()  # pylint: disable=no-value-for-parameter
