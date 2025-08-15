MAC_ADDRESS = {
    "vmware": "00:05:69",
    "broadcom": "00:05:B5",
    "samsung": "FC:42:03",
    "cisco": "00:27:0D"
}

ETHER_TYPES = {
    "ipv4": 0x0800,
    "ipv6": 0x86dd, 
}

TCP_FLAGS = {
    "s": "syn",
    "a": "ack",
    "f": "fin",
    "r": "rst",
    "p": "psh",
    "u": "urg",
}

TCP_PORTS = {
    "$http_ports": [80, 443, 8080, 8443],
    "$ssh_ports": [22, 2222],
    "$ftp_ports": [21],
    "$smtp_ports": [25, 589],
}

UDP_PORTS = {}