
def external_addresses(data):
    return [line for line in data if not line[1].startswith(('10.' ,'192.168'))]

def filtering_by_sensitive_port(data):
    return [line for line in data if line[3] in ('22', '3389' , '23')]

def filter_by_size(data,size):
    return [line for line in data if int(line[5]) > size]

def tag_traffic_by_size(data , size):
    return [line + ["LARGE"] if int(line[5]) > size else line + ["NORMAL"] for line in data]