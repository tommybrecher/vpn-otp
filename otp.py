#! /usr/bin/env python
import sys
import pyotp
import base64
import pexpect
import click

help = "v -> VPN V\n o -> VPN O\n p -> VPN P"

@click.command()
@click.option('--vpn', default='v', type=click.Choice(['v','o','p']), help=help)
@click.option('--debug', is_flag=True, help='Enable debugging - prints output to stdout')
def main(vpn, debug):
    username = 'XXXX'
    pwd = base64.b64decode('XXXX')

    while True:

        totp = pyotp.totp.TOTP('XXXX')
        password = '{}{}'.format(pwd, totp.now())

        if vpn == 'v':
            command = 'path/to/vpn-v.ovpn'

        elif vpn == 'o':
            command = '/path/to/vpn-o.ovpn'

        elif vpn == 'p':
            command = 'openconnect --juniper url.of.vpn-p.com'

        else:
            sys.exit()

        if vpn == 'p':

            process = pexpect.spawn(command)

            if debug:
                process.logfile = sys.stdout

            try:
                process.expect('username:')
                process.sendline(username)
                process.expect('password:')
                process.sendline(password)
                print 'Connected'

                while True:
                    process.expect('.+', timeout=None)
                    output = process.match.group(0)
                    if output != '\r\n':
                        print 'openconnect: ', output
                        break

            except pexpect.EOF:
                print 'Invalid username and/or password'

            except pexpect.TIMEOUT:
                print 'Connection failed!'

        else:

            process = pexpect.spawn(command)

            if debug:
                process.logfile = sys.stdout

            try:
                process.expect('Enter Auth Username:')
                process.sendline(username)
                process.expect('Enter Auth Password:')
                process.sendline(password)
                print 'Attempting connection'
                process.expect('Initialization Sequence Completed')
                print 'Connected'
                # Attempt reconnection
                while True:
                    process.expect('.+', timeout=None)
                    output = process.match.group(0)
                    if output != '\r\n':
                        print 'openvpn: ', output
                        break

            except pexpect.EOF:
                print 'Invalid username and/or password'

            except pexpect.TIMEOUT:
                print 'Cannot connect to OpenVPN server!'


if __name__ == '__main__':
    main()
