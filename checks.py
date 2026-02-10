import config

def external_addresses(data):
    return [line for line in data if not line[1].startswith(config.EXTERNAL_IP)]

def filtering_by_sensitive_port(data):
    return [line for line in data if line[3] in config.SENSITIVE_PORT]

def filter_by_size(data):
    return [line for line in data if int(line[5]) > config.PACKET_LARGE]

def tag_traffic_by_size(data):
    return [line + ["LARGE"] if int(line[5]) > config.PACKET_LARGE else line + ["NORMAL"] for line in data]

def message_at_forbidden_time(data):
    return [line for line in data if int(config.NIGHT_ACTIVITY[0]) <= int(line[0].split()[1][:2]) < int(config.NIGHT_ACTIVITY[1])]