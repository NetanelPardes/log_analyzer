
def read_network_file(filename):
    with open(filename, 'r' , encoding="utf-8") as f:
        return [line.strip().split(',') for line in f.readlines()]

def read_log_generator(path):
    with open(path, 'r', encoding='utf-8') as f:
        for line in f:
            yield line.strip().split(',')