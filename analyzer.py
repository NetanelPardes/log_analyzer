import checks

def identifying_suspicions(data):
    external_addresses_list = checks.external_addresses(data)
    sensitive_port_list  = checks.filtering_by_sensitive_port(data)
    large_packet_list  = checks.filter_by_size(data)
    forbidden_time_list = checks.message_at_forbidden_time(data)

    suspicions = {}

    for line in data:
        suspicions[line[1]] = []

    for line in data:

        if line in external_addresses_list:
            if "EXTERNAL_IP" not in suspicions[line[1]]:
                suspicions[line[1]].append("EXTERNAL_IP")

        if line in sensitive_port_list:
            if "SENSITIVE_PORT" not in suspicions[line[1]]:
                suspicions[line[1]].append("SENSITIVE_PORT")

        if line in large_packet_list:
            if "LARGE_PACKET" not in suspicions[line[1]]:
                suspicions[line[1]].append("LARGE_PACKET")

        if line in forbidden_time_list:
            if "NIGHT_ACTIVITY" not in suspicions[line[1]]:
                suspicions[line[1]].append("NIGHT_ACTIVITY")
    return suspicions

