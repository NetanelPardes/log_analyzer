from checks import check_row

# from log_analyzer.log_analyzer import reporter
#
#
# def identifying_suspicions(data):
#     external_addresses_list = checks.external_addresses(data)
#     sensitive_port_list  = checks.filtering_by_sensitive_port(data)
#     large_packet_list  = checks.filter_by_size(data)
#     forbidden_time_list = checks.message_at_forbidden_time(data)
#
#     suspicions = {}
#
#     for line in data:
#         suspicions[line[1]] = []
#
#     for line in data:
#
#         if line in external_addresses_list:
#             if "EXTERNAL_IP" not in suspicions[line[1]]:
#                 suspicions[line[1]].append("EXTERNAL_IP")
#
#         if line in sensitive_port_list:
#             if "SENSITIVE_PORT" not in suspicions[line[1]]:
#                 suspicions[line[1]].append("SENSITIVE_PORT")
#
#         if line in large_packet_list:
#             if "LARGE_PACKET" not in suspicions[line[1]]:
#                 suspicions[line[1]].append("LARGE_PACKET")
#
#         if line in forbidden_time_list:
#             if "NIGHT_ACTIVITY" not in suspicions[line[1]]:
#                 suspicions[line[1]].append("NIGHT_ACTIVITY")
#     return suspicions
#
# def at_least_two_suspicions(ip_dict):
#     return {k: v for k, v in ip_dict.items() if len(v) >= 2}
#
# def package_size_conversion(data):
#     return list(map(lambda line: round(float(line[5]) / 1024, 2) , data))
#
# def get_row_suspicions(data):
#     for line in data:
#         analyze_log_with_suspicions1 = reporter.analyze_log_with_suspicions(line)

def filter_suspicious(rows, checks):
    for row in rows:
        if check_row(row, checks):
            yield row

def add_suspicion_details(rows, checks):
    for row in rows:
        yield row, check_row(row, checks)

from reader import read_log_generator
from checks import suspicion_checks, check_row
from reporter import update_statistics

def analyze_log(filepath):
    checks = suspicion_checks()
    suspicious_ips = {}

    for row in read_log_generator(filepath):
        suspicions = check_row(row, checks)

        update_statistics(suspicions)

        if suspicions:
            ip = row[1]
            suspicious_ips.setdefault(ip, set()).update(suspicions)

    # המרה חזרה לרשימות (כדי להדפיס יפה)
    return {ip: list(tags) for ip, tags in suspicious_ips.items()}


