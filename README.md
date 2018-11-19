vipaccess-go: a client for provisioning credentials from the Symantec VIP Access service.

[![GoDoc](https://godoc.org/github.com/athomason/vipaccess-go?status.png)](https://godoc.org/github.com/athomason/vipaccess-go)
[![TravisCI Build](https://travis-ci.org/athomason/vipaccess-go.svg)](https://travis-ci.org/athomason/vipaccess-go)

vipaccess-go is a partial Go port of [https://www.cyrozap.com/2014/09/29/reversing-the-symantec-vip-access-provisioning-protocol/](https://www.cyrozap.com/2014/09/29/reversing-the-symantec-vip-access-provisioning-protocol/). The command line tool [`vipaccess`](cmd/vipaccess) invents a request simulating a random iMac and requests a new credential for it, then outputs the otpauth URI containing the OTP secret. Optionally it can write out a PNG file containing a QR code that encodes the URI for easy import into OTP clients like Google Authenticator or 1password.

See also the [blog post](https://www.cyrozap.com/2014/09/29/reversing-the-symantec-vip-access-provisioning-protocol/) describing how the original author reverse engineered the VIP Access protocol.
