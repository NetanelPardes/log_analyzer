def Number_uses_network(data):
    return {row[1]: [r[1] for r in data].count(row[1]) for row in data}

def protocol_name_and_port_number(data):
    return {row[3]: row[4] for row in data}

def crate_hours_list(data):
    return list(map(lambda line: int(line[0].split()[1].split(':')[0]), data))