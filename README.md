# FKM-PROXY
Simple yet powerful proxy for http(s) traffic (can also handle websockets).


## Features
- TCP proxy (all kinds of http(s) traffic - like websockets, http/2, etc.)
- E2E encryption (while using own https certificate on own domain)
- Tunneling is done using TLS for secure connection between proxy server and client


## How to setup E2E encryption:
While doing this, proxy server won't be able to see any plain-text traffic from and to your client.
All traffic will be encrypted using your own ssl on your own local webserver (fkm-proxy-client isn't using your generated cert).

1. Add `CNAME` record to your domain pointing to `vps.filipton.space` (this is my primary proxy server)
2. Generate certificate for your domain (using for example lets encrypt - with DNS verification)
3. Setup your webserver to use that certificate (for example nginx)
4. Pass `--ssl-addr` argument with ip:port to your webserver(https) (for example localhost:443)
> [!IMPORTANT]
> --ssl-addr isn't overwriting --addr, so you need to pass both addresses in that case

> [!NOTE]
> If you are using https redirection (from fkm-proxy-client binary), you also need to set `--addr` argument (you can set anything, it won't be used)

## Dev
### Server
To run dev server use this command (with local ssl cert generation):
```bash
BIND_NONSSL=0.0.0.0:8080 BIND_SSL=0.0.0.0:8443 cargo run --bin fkm-proxy-server -- --domain testlocal.filipton.space --generate-cert
```

> [!NOTE]
> *.testlocal.filipton.space is pointing to 127.0.0.1. You can also just use localhost as your domain.


To create new tunnel use your browser, and type panel url, or generate it using simple CURL:
```bash
curl -X POST http://testlocal.filipton.space:8080/create?url=test
```
> [!IMPORTANT]
> Panel domain can be specified using --panel-domain argument, by default its using --domain argument value.

It will return something like this:
```json
{"url":"test","hash":"10426308271401697964","token":"178744005062729538121086180162812072708"}
```


### Client
To run client (using custom proxy server) use this command:
```bash
cargo run --bin fkm-proxy-client -- --hash 10426308271401697964 --token 178744005062729538121086180162812072708 -a 127.0.0.1:5000 -p localhost:6969
```
> [!NOTE]  
> Change your `HASH` and `TOKEN` to values previously generated on server.

> [!IMPORTANT]
> You can specify Proxy ip using `-p` argument (by default proxy server is running on port 6969)


While running your client, you can easily see your access url's:
```
Access through:
 - http://test.testlocal.filipton.space:8080
 - https://test.testlocal.filipton.space:8443
```
