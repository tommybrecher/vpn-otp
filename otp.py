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


def read_config(salt=None):
    """
    Reads the configuration file or create a new one if missing 
    """
    cfg_dir = click.get_app_dir('pyotp', force_posix=True)
    cfg = join(cfg_dir, 'config')
    parser = ConfigParser()

    if exists(cfg):
        parser.read(cfg)
        salt = bytes.fromhex(
            parser['default']['salt']
        )
        token = bytes.fromhex(
            parser['default']['token']
        )
        return salt, token

    if not exists(cfg_dir):
        print(f'Generating new configuration file at: {cfg}')
        makedirs(cfg_dir, exist_ok=True)
   
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
        'pulse': f'openconnect --no-dtls -q --juniper -u {username} {pulse_url}'
    }

    if creds_only:
        print(f'--user={username} --password={password}{otptoken.now()}')
        exit()

    while True:
        if ('va' in vpn or 'or' in vpn):
            process = pexpect.spawn(
                f'{commands[vpn]}',
                encoding='utf-8',
                logfile=log_level
            )

            try:
                process.expect('Password:')
                process.sendline(password)

                process.expect('Enter Auth Username:')
                process.sendline(username)

                process.expect('Enter Auth Password:')
                process.sendline(f'{password}{otptoken.now()}')

                process.expect('Initialization Sequence Completed')

                print('Connected')

                while True:
                    process.expect('.+', timeout=None)
                    output = process.match.group(0)

                    if output != '\r\n':
                        print(f'openvpn: {output}')
                        break

            except pexpect.EOF:
                print('Invalid username and/or password')

            except pexpect.TIMEOUT:
                print('Cannot connect to OpenVPN server!')

        elif 'pulse' in vpn:

            process = pexpect.spawn(f'{commands[vpn]}', encoding='utf-8', logfile=log_level)
            try:
                process.expect('password:')
                process.sendline(f'{password}{otptoken.now()}')
                print('Connected')

                while True:
                    process.expect(r'(error|invalid|failed)/ig', timeout=None)
                    output = process.match.group(0)

                    if output != '\r\n':
                        print(f'openconnect: {output}')
                        break

            except pexpect.EOF:
                print('Invalid username and/or password')

            except pexpect.TIMEOUT:
                print('Connection failed!')


if __name__ == '__main__':
    # Getting credentials and reading config file
    username, password = getuser(), getpass()
    salt, token = read_config()
    
    # Decryption of the key 
    fernet = crypt(password, salt)
    token = fernet.decrypt(token).decode()

    # Creating an instance of pyotp 
    otptoken = pyotp.totp.TOTP(token)

    # Launching the script
    main()
