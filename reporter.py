import config


def Number_uses_network(data):
    return {row[1]: [r[1] for r in data].count(row[1]) for row in data}

def protocol_name_and_port_number(data):
    return {row[3]: row[4] for row in data}

def crate_hours_list(data):
    return list(map(lambda line: int(line[0].split()[1].split(':')[0]), data))

def create_suspicion_checkers():
    return {
        "EXTERNAL_IP": lambda line: line[1] in config.EXTERNAL_IP,
        "SENSITIVE_PORT": lambda line: line[3] in config.SENSITIVE_PORT,
        "LARGE_PACKET": lambda line: int(line[5]) > config.PACKET_LARGE,
        "NIGHT_ACTIVITY": lambda line : int(config.NIGHT_ACTIVITY[0]) <= int(line[0].split()[1][:2]) < int(config.NIGHT_ACTIVITY[1])
    }

def run_suspicion_checks(line, checkers):
    return list(map(lambda item: item[0],filter(lambda item: item[1](line),checkers.items())))

def analyze_log_with_suspicions(log_lines, checkers):
    return list(filter(lambda result: len(result[1]) > 0,map(lambda line: (line, run_suspicion_checks(line, checkers)),log_lines)))