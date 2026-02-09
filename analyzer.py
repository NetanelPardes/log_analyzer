
def external_addresses(data):
    return [line for line in data if not line[1].startswith(('10.' ,'192.168'))]
