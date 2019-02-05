This repository is a fork of the Go core standard library: [https://github.com/golang/go/tree/master/src/crypto](https://github.com/golang/go/tree/master/src/crypto)

This repository also includes embedded sources from other projects, including:
* https://github.com/flynn/hid
* https://github.com/flynn/u2f

Please refer to those libraries for respective licenses.

Usage
=====

Because this is a fork of the Go core standard library, you need to replace your distribution's library with this one. It also integrates with core library internal packages, so it may only be compatible with specific releases. At the time of writing it has been tested with go1.12beta2.

You can replace your distribution's core library with this one by running some version of the following:

```
cd $(dirname $(which go))/../src
rm -rf crypto
git clone https://github.com/JackOfMostTrades/go-crypto crypto
```

Enhancements
============

This library contains proof-of-concept enhancements and features. It's not intended for production use, but feel free to play with it.

This fork adds support for using U2F tokens to authenticate mutual TLS connections. Rather than needing to implement the U2F authentication flow in the application layer, this enhancement allows you to create client certificates which embed a reference to a U2F-token's public key and authenticates client connections with a U2F authentication response. This allows you to use U2F in contexts where modifying the application layer might be difficult or impossible. It also allows you to take advantage of the distributed and stateless nature of PKI; instead of requiring that the server maintain a mapping from usernames to U2F tokens and key handles the server only needs to verify the X.509 client certificate as usual.

Is this a good idea? No, probably not. It's just a proof-of-concept.
