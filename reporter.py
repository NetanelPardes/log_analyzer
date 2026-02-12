import config
import matplotlib.pyplot as plt

def Number_use_network(data):
    return {row[1]: [r[1] for r in data].count(row[1]) for row in data}

def protocol_name_and_port_number(data):
    return {row[3]: row[4] for row in data}

def crate_hours_list(data):
    return list(map(lambda line: int(line[0].split()[1].split(':')[0]), data))

def run_suspicion_checks(line, checkers):
    return [
        name
        for name, checker in checkers.items()
        if checker(line)
    ]


def analyze_log_with_suspicions(log_lines):
    checkers = {
        "EXTERNAL_IP": lambda line: line[1] in config.EXTERNAL_IP,
        "SENSITIVE_PORT": lambda line: line[3] in config.SENSITIVE_PORT,
        "LARGE_PACKET": lambda line: int(line[5]) > config.PACKET_LARGE,
        "NIGHT_ACTIVITY": lambda line : int(config.NIGHT_ACTIVITY[0]) <= int(line[0].split()[1][:2]) < int(config.NIGHT_ACTIVITY[1])
    }

    return list(filter(lambda result: len(result[1]) > 0,map(lambda line: (line, run_suspicion_checks(line, checkers)),log_lines)))

def analyze_log_with_suspicions_by_yield(lines):
    checkers = {
        "EXTERNAL_IP": lambda line: not line[1].startswith(config.EXTERNAL_IP),
        "SENSITIVE_PORT": lambda line: line[3] in config.SENSITIVE_PORT,
        "LARGE_PACKET": lambda line: int(line[-1]) > config.PACKET_LARGE,
        "NIGHT_ACTIVITY": lambda line:
            int(config.NIGHT_ACTIVITY[0])
            <= int(line[1][:2])
            < int(config.NIGHT_ACTIVITY[1]),
    }

    for line in lines:
        if len(line) < 6:
            continue

        suspicions = run_suspicion_checks(line, checkers)
        if suspicions:
            yield line, suspicions

def count_items(generator):
    return sum(1 for _ in generator)


total_lines = 0
suspicious_lines = 0
suspicion_counter = {
    "EXTERNAL_IP": 0,
    "SENSITIVE_PORT": 0,
    "LARGE_PACKET": 0,
    "NIGHT_ACTIVITY": 0
}

def update_statistics(suspicions):
    global total_lines, suspicious_lines, suspicion_counter

    total_lines += 1

    if suspicions:
        suspicious_lines += 1
        for s in suspicions:
            suspicion_counter[s] += 1

def generate_report(suspicious_dict):
    lines = []
    lines.append("=" * 40)
    lines.append("דוח תעבורה חשודה")
    lines.append("=" * 40)

    lines.append("\nסטטיסטיקות כלליות:")
    lines.append(f"- שורות שנקראו: {total_lines}")
    lines.append(f"- שורות חשודות: {suspicious_lines}")

    for k, v in suspicion_counter.items():
        lines.append(f"- {k}: {v}")

    lines.append("\nIPs עם רמת סיכון גבוהה (+3 חשדות):")
    for ip, tags in suspicious_dict.items():
        if len(tags) >= 3:
            lines.append(f"- {ip}: {', '.join(tags)}")

    lines.append("\nIPs חשודים נוספים:")
    for ip, tags in suspicious_dict.items():
        if len(tags) < 3:
            lines.append(f"- {ip}: {', '.join(tags)}")

    return "\n".join(lines)

def save_report(report, filepath):
    with open(filepath, 'w', encoding='utf-8') as f:
        f.write(report)

def plot_suspicion_distribution():
    labels = []
    values = []

    for k, v in suspicion_counter.items():
        if v > 0:
            labels.append(k)
            values.append(v)

    plt.figure()
    plt.pie(values, labels=labels, autopct='%1.1f%%')
    plt.title("התפלגות סוגי חשדות")
    plt.show()
def plot_top_suspicious_ips(suspicious_dict, top_n=10):
    ip_counts = {
        ip: len(tags)
        for ip, tags in suspicious_dict.items()
    }

    sorted_ips = sorted(
        ip_counts.items(),
        key=lambda x: x[1],
        reverse=True
    )[:top_n]

    ips = [item[0] for item in sorted_ips]
    counts = [item[1] for item in sorted_ips]

    plt.figure(figsize=(10, 5))
    plt.bar(ips, counts)
    plt.title("כתובות IP עם הכי הרבה חשדות")
    plt.xlabel("IP")
    plt.ylabel("מספר חשדות")
    plt.xticks(rotation=45, ha="right")
    plt.tight_layout()
    plt.show()
