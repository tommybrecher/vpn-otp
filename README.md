# vpn-otp
Connect to openconnect VPNs which require OTP password automatically
with automatic reconnection on disconnect.

# Dependencies:
- OpenConnect (for connecting to OpenConnect based VPNs)

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

<code>pipenv run pyotp-vpn</code>

It might be beneficial to make a patch which includes proprietary information for your organization.

Configuration arguments:
args = Any configuration flags that would normally be passed to openconnect, for example --no-dtls or --protocol=pulse
routes = a new-line seperated list of prefixes (routes) to be added by vpn-slice (Split-tunnel allowed networks)
domains = a new-line seperated list of domain names we want to add a resolver for (DNS via VPN)
# Example ~/.pyotp/config file
```
[pulse]
args = --protocol=pulse --no-dtls <--other-options--> <--vpn-url-->
routes =
        10.0.0.0/8
        172.16.0.0/12
        8.8.8.0/24

domains =
        domain1.com
        domain2.com
        domain3.com
```
