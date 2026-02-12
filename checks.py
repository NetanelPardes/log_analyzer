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

def filter_by_port(data):
    return list(filter(lambda line: line[3] in config.SENSITIVE_PORT, data))

def filter_by_time(data):
    return list(filter(lambda line : int(config.NIGHT_ACTIVITY[0]) <= int(line[0].split()[1][:2]) < int(config.NIGHT_ACTIVITY[1]) , data))

def suspicion_checks():
    return {
        "EXTERNAL_IP": lambda r: not r[1].startswith(('192.168.', '10.')),
        "SENSITIVE_PORT": lambda r: r[3] in ('22', '23', '3389'),
        "LARGE_PACKET": lambda r: int(r[5]) > 5000,
        "NIGHT_ACTIVITY": lambda r: 0 <= int(r[0].split()[1][:2]) < 6
    }

def check_row(row, checks):
    return list(
        map(
            lambda item: item[0],
            filter(lambda item: item[1](row), checks.items())
        )
    )

