#! /usr/bin/env python3
import sys
import pyotp
import base64
import pexpect
import click

@click.command()
@click.option('--vpn', default='v', type=click.Choice(['v', 'o', 'p']))
@click.option('--debug', is_flag=True, help='Enable debugging - prints output to stdout')
@click.option('--creds-only', is_flag=True, help='prints out the credentials only')
def main(vpn, debug, creds_only):

    log_level = sys.stdout if debug else None
    username = ''
    totp = pyotp.totp.TOTP('')
    pwd = base64.b64decode('').decode()
    config_path = ''
    pulse_url = ''

    vpn_commands = {
        'v': f'openvpn {config_path}/v.ovpn',
        'o': f'openvpn {config_path}/o.ovpn',
        'p': f'openconnect --no-dtls -q --juniper -u {username} {pulse_url}'
    }

    if creds_only:
        print(f'--user={username} --password={pwd}{totp.now()}')
        sys.exit(0)

    while True:

        if (vpn == 'v' or vpn == 'o'):

            process = pexpect.spawn(f'{vpn_commands[vpn]}', encoding='utf-8', logfile=log_level)
            try:
                process.expect('Enter Auth Username:')
                process.sendline(username)
                process.expect('Enter Auth Password:')
                process.sendline(f'{pwd}{totp.now()}')
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

        elif vpn == 'p':

            process = pexpect.spawn(f'{vpn_commands[vpn]}', encoding='utf-8', logfile=log_level)
            try:
                process.expect('password:')
                process.sendline(f'{pwd}{totp.now()}')
                print('Connected')
                process.interact()

                while True:
                    process.match('(error|invalid|failed)/ig', timeout=None)
                    output = process.match.group(0)
                    if output != '\r\n':
                        print(f'openconnect: {output}')
                        break

            except pexpect.EOF:
                print('Invalid username and/or password')

            except pexpect.TIMEOUT:
                print('Connection failed!')


if __name__ == '__main__':
    main()
