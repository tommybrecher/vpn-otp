# vpn-otp
Connect to openvpn/openconnect VPNs which require OTP password automatically
and automatically reconnect on disconnect.

# Dependencies:
- OpenVPN (for connecting to openVPN based connections)
- OpenConnect (for conneting to OpenConnet based VPN connections)

# Installation on macOS
Installing Brew requirments:
<code>brew install openconnect openvpn</code>

Installing Python requirments:
<code>pip3 install -r requirments.txt</code>

# Configure:

A Prompt will appear when running this app for the first time,
A configuration file will be generated in users home folder:

<code> ~/.pyotp/config</code>

# Usage:
Note: the default option is --vpn=va

<code>sudo ./otp.py --vpn <va/or/pulse></code>

It might be beneficial to make a patch which includes proprietary information for your organization,
to apply the patch, make sure the patch is in the repository folder and apply it by running:

<code>patch < add_proprietary_resources.patch </code>
