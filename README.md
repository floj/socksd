# socksd
A completely featureless SOCKS V5 proxy server.

Supported authentication methods
- NO AUTHENTICATION REQUIRED `X'00'`
- ~~GSSAPI (RFC 2743) `X'01'`~~
- ~~USERNAME/PASSWORD `X'02'`~~

Supported connection commands
- CONNECT `X'01'`
- ~~BIND `X'02'`~~
- ~~UDP ASSOCIATE `X'03'`~~

Installation:
```
go get github.com/floj/socksd
```
Usage:
```
./socksd -port 8888
```
Todo:
- [ ] Unit tests
