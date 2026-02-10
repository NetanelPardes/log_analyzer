def Number_uses_network(data):
    return {row[1]: [r[1] for r in data].count(row[1]) for row in data}