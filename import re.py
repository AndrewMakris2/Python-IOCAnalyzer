import re

def classify_ioc(ioc):
    if re.match(r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$", ioc):
        return "ip"
    elif re.match(r"^https?://", ioc):
        return "url"
    elif re.match(r"^[a-fA-F0-9]{32}$", ioc):
        return "md5"
    elif re.match(r"^[a-fA-F0-9]{40}$", ioc):
        return "sha1"
    elif re.match(r"^[a-fA-F0-9]{64}$", ioc):
        return "sha256"
    elif re.match(r"^(?!:\/\/)([a-zA-Z0-9-_]+\.)+[a-zA-Z]{2,11}?$", ioc):
        return "domain"
    else:
        return "unknown"
