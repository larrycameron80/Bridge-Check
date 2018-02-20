#!/usr/bin/python3 -u

import re

ipv4 = re.compile("^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$")
ipv6 = re.compile("^\[(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))\]$")
port = re.compile("^[0-9]{1,5}$")
fingerprint = re.compile("^[A-Z0-9]{40}$")
cert = re.compile("^cert=(.{70}$)")
mode = re.compile("^iat-mode=[0-9]$")
url= re.compile("^url=(.+)$")
front= re.compile("^front=(.+)$")

def bridge_check(line):
    parts = line.split()

    if parts[0] == 'obfs4':
        if len(parts) != 5:
            return "Wrong number of arguments in bridge syntax"
        if not ipv4.match(parts[1].split(":")[0]) and not ipv6.match(parts[1].split(":")[0]):
            return "Invalid IP: {}".format(parts[1].split(":")[0])
        if not port.match(parts[1].split(":")[1]):
            return "Invalid Port Number: {}".format(parts[1].split(":")[1])
        if not fingerprint.match(parts[2]):
            return "Invalid Fingerprint: {}".format(parts[2])
        if not cert.match(parts[3]):
            return "Invalid Cert: {}".format(parts[3])
        if not mode.match(parts[4]):
            return "Invalid iat-mode: {}".format(parts[4])
        return "Valid {} brdige".format(parts[0])
    elif parts[0] == 'obfs3' or parts[0] == 'fte':
        if len(parts) != 3:
            return "Wrong number of arguments in bridge syntax"
        if not ipv4.match(parts[1].split(":")[0]) and not ipv6.match(parts[1].split(":")[0]):
            return "Invalid IP: {}".format(parts[1].split(":")[0])
        if not port.match(parts[1].split(":")[1]):
            return "Invalid Port Number: {}".format(parts[1].split(":")[1])
        if not fingerprint.match(parts[2]):
            return "Invalid Fingerprint: {}".format(parts[2])
        return "Valid {} brdige".format(parts[0])
    elif parts[0] == 'meek_lite' or parts[0] == 'meek':
        if len(parts) != 5:
            return "Wrong number of arguments in bridge syntax"
        if not ipv4.match(parts[1].split(":")[0]) and not ipv6.match(parts[1].split(":")[0]):
            return "Invalid IP: {}".format(parts[1].selfplit(":")[0])
        if not port.match(parts[1].split(":")[1]):
            return "Invalid Port Number: {}".format(parts[1].split(":")[1])
        if not fingerprint.match(parts[2]):
            return "Invalid Fingerprint: {}".format(parts[2])
        if not url.match(parts[3]):
            return "Invalid url: {}".format(parts[3])
        if not front.match(parts[4]):
            return "Invalid front: {}".format(parts[4])
        return "Valid {} brdige".format(parts[0])
    else:                           # assume to be vanilla bridges
        if len(parts) != 2:
            return "Wrong number of arguments in bridge syntax"
        if not ipv4.match(parts[0].split(":")[0]) and not ipv6.match(parts[0].split(":")[0]):
            return "Invalid IP: {}".format(parts[0].split(":")[0])
        if not port.match(parts[0].split(":")[0]):
            return "Invalid Port Number: {}".format(parts[0].split(":")[1])
        if not fingerprint.match(parts[1]):
            return "Invalid Fingerprint: {}".format(parts[1])
        return "Valid {} brdige".format("Vanilla")
