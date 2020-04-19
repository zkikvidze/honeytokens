# honeytokens
My implementation of canarytokens

honeytokens.py - Main file, http and dns server, parser and log forwarder to syslog, SIEM, email. you can run it with your favorite service manager, you can find sample systemd unit file in the repo. not recommended to run it with root permissions, use port forwarding or other approaches to make it listen <1024 ports.

generate.py - Generate payload, currently supported .doc and desktop.ini payloads. see -h for help.

search.py - Just queries json.

for now, there is no error checking (mostly) and lacks lots of things. but works. tested on python 3.8
