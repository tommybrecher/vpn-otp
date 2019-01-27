#! /usr/bin/env python3
import sys
import pyotp
import base64
import pexpect
import click
from os.path import join, exists
from os import makedirs
from getpass import getuser, getpass
from configparser import ConfigParser


def read_config():
    """
    Reads the configuration file or create a new one if missing 
    """
    cfg_dir = click.get_app_dir('pyotp', force_posix=True)
    cfg = join(cfg_dir, 'config')
    parser = ConfigParser()

    if exists(cfg):
        with open(file=cfg, mode='r') as config_file:
            parser.read(cfg)
        return parser

    if not exists(cfg_dir):
        """
        Create directory and config file
        """
        print(f'Generating new configuration file at: {cfg}')
        makedirs(cfg_dir, exist_ok=True)

    parser['default'] = dict(
        username=getuser(),
        password=getpass(),
        otptoken=input('Token: ')
    )

    with open(file=cfg, mode='w') as config_file:
        parser.write(config_file)

    return parser


@click.command()
@click.option('--vpn', default='va', type=click.Choice(['va', 'or', 'pulse']))
@click.option('--debug', is_flag=True, help='Prints output to stdout')
@click.option('--creds-only', is_flag=True, help='Only prints credentials')
def main(vpn, debug, creds_only):
    log_level = sys.stdout if debug else None
    cfg_path = ''
    pulse_url = ''
    commands = {
        'va': f'openvpn {cfg_path}/va.ovpn',
        'or': f'openvpn {cfg_path}/or.ovpn',
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
    global username, password, otptoken
    cfg = read_config()
    username = cfg['default']['username']
    password = cfg['default']['password']
    otptoken = pyotp.totp.TOTP(cfg['default']['otptoken'])
    main()
