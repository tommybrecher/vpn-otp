# vpn-otp
Connect to openconnect VPNs which require OTP password automatically
and automatically reconnect on disconnect.

# Dependencies:
- OpenConnect (for conneting to OpenConnet based VPN connections)

# Installation on macOS
Installing Brew requirments:
<code>brew install openconnect</code>

Installing Python requirments:
<code>pipenv install</code>

# Configure:

A Prompt will appear when running this app for the first time,
A configuration file will be generated in users home folder:

<code> ~/.pyotp/config</code>

# Usage:

<code>sudo pipenv run pyotp-vpn</code>

It might be beneficial to make a patch which includes proprietary information for your organization,
to apply the patch, make sure the patch is in the repository folder and apply it by running:
