# l9synscan

[![GitHub Release](https://img.shields.io/github/v/release/LeakIX/l9synscan)](https://github.com/LeakIX/l9synscan/releases)
[![Follow on Twitter](https://img.shields.io/twitter/follow/leak_ix.svg?logo=twitter)](https://twitter.com/leak_ix)

l9synscan is an IPv4/IPv6 SYN scanner taking hosts ( by IP ) from stdin in l9format.

## Features

- IPv4 + IPv6
- Caches IP/hostnames open ports
- Configurable output of events by hostname
- Suitable input would be [dnsx](https://github.com/projectdiscovery/dnsx) through l9filter
- Suitable output for l9tcpid
- Rate limiting

## Usage

```sh
▶ l9synscan scan -h
```

Displays help for the service command (only implementation atm)

|Flag           |Description  |
|-----------------------|-------------------------------------------------------|
|--ports            | List of ports to scan
|--rate-limit       | Limit outgoing pps
|--timeout          | Time to wait for ACKs
|--source-port      | Source port to scan from
|--source-ip4       | Source ipv4 to scan from
|--source-ip6       | Source ipv6 to scan from
|--disable-dup      | Disable duplication of events based on hostname

## Installation Instructions

### From Binary

libpcap is required to run this software, check your distribution's package manager.

The installation is easy. You can download the pre-built binaries for your platform from the [Releases](https://github.com/LeakIX/l9synscan/releases/) page.

```sh
▶ apt-get install -y libpcap0.8
▶ chmod +x l9synscan-linux-64
▶ mv l9synscan-linux-64 /usr/local/bin/l9synscan
```

### From Source

You're going to need libpcap's headers and **go1.14+** to built l9synscan.

```sh
▶ apt-get install -y libpcap-dev
▶ GO111MODULE=on go get -u -v github.com/LeakIX/l9synscan/cmd/l9synscan
▶ ${GOPATH}/bin/l9synscan scan -h
```


## Running l9synscan

### l9format

l9synscan speaks [l9format](https://github.com/LeakIX/l9format). [l9filter](https://github.com/LeakIX/l9filter) can be used to manage 
input/output from this module.

### Running with l9synscan from DNS enumeration

```sh 
▶ cat subdomains-top100000.txt | \
  awk {'print $1".google.com"'} | \
  dnsx -json | l9filter tranform -i dnsx -o l9format | \
  l9synscan scan -p 1-10000 -i eth0 --rate-limit 20000 | \
  l9tcpid service --deep-http --max-threads 512 | \
  l9explore service --max-threads 512 | tee services.json | \
  l9filter transform -i l9 -o human

Found service at 209.85.145.113 (account.google.com) on port 443 PROTO:https SSL:true
HTTP/1.1 302 Found
Location: https://myaccount.google.com/
Cache-Control: private
Content-Type: text/html; charset=UTF-8
X-Content-Type-Options: nosniff
Date: Wed, 06 Jan 2021 18:27:38 GMT
Server: sffe
Content-Length: 226
X-XSS-Protection: 0
Alt-Svc: h3-29=":443"; ma=2592000,h3-T051=":443"; ma=2592000,h3-Q050=":443"; ma=2592000,h3-Q046=":443"; ma=2592000,h3-Q043=":443"; ma=2592000,quic=":443"; ma=2592000; v="46,43"
Connection: close

Page title: 302 Moved

....
```
