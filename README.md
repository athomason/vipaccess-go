vipaccess-go: a client for provisioning credentials from the Symantec VIP Access service.

[![Documentation](https://godoc.org/github.com/athomason/vipaccess-go?status.svg)](https://godoc.org/github.com/athomason/vipaccess-go) [![Build](https://travis-ci.org/athomason/vipaccess-go.svg?branch=master)](https://travis-ci.org/athomason/vipaccess-go) [![License](https://img.shields.io/github/license/athomason/vipaccess-go.svg?maxAge=2592000)](https://github.com/athomason/vipaccess-go/LICENSE) [![Release](https://img.shields.io/github/release/athomason/vipaccess-go.svg?label=Release)](https://github.com/athomason/vipaccess-go/releases)

vipaccess-go is a partial [Go](https://golang.org) port of [@cyrozap's python-vipaccess](https://github.com/cyrozap/python-vipaccess). The command line tool [`vipaccess`](cmd/vipaccess) invents a request simulating a random iMac and requests a new credential for it, then outputs the otpauth URI containing the OTP secret. Optionally it can write out a PNG file containing a QR code that encodes the URI for easy import into OTP clients like Google Authenticator or 1password.

See also the [blog post](https://www.cyrozap.com/2014/09/29/reversing-the-symantec-vip-access-provisioning-protocol/) describing how the original author reverse engineered the VIP Access protocol.
