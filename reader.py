
def read_network_file(filename):
    with open(filename, 'r' , encoding="utf-8") as f:
        return [line.strip().split(',') for line in f.readlines()]

