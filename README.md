# vpn-otp
Connect to openvpn/openconnect VPNs which require OTP password automatically
and automatically reconnect on disconnect.

# Dependencies:
- OpenVPN (for connecting to openVPN based connections)
- OpenConnect (for conneting to OpenConnet based VPN connections)

# Installation on macOS
```
brew install openconnect openvpn
pip2.7 install -r requirments.txt
```

# Configure:

Replace XXXX with your username

<code>username = 'XXXX'</code>

Replace XXXX with your password (base64 encoded)

<code>pwd = base64.b64decode('XXXX')</code>

Replace XXXX with your TOTP token 

<code>totp = pyotp.totp.TOTP('XXXX')</code>

# Encoding string to base64 with python2.7
```
#! /usr/bin/env python
import base64
print(base64.b64encode('string_to_encode'))
c29tZV9zdHJpbmc=
```

# Usage:
Note: the default option is --vpn=v

<code>sudo python2.7 otp.py --vpn <v/o/p></code>

It might be beneficial to make a patch which includs proprietary information for your organization,
to apply the patch, make sure the patch is in the repository folder and apply it by running:

<code>patch < add_proprietary_resources.patch </code>
