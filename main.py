from reader import read_network_file
from analyzer import external_addresses, filtering_by_sensitive_port

def main():
    my_path = 'C:\\Users\\sendi\\PycharmProjects\\PythonProject1\\log_analyzer\\log_analyzer\\network_traffic.log'
    network_line = read_network_file(my_path)
    external_IP_addresses = external_addresses(network_line)
    # for ip in external_IP_addresses:
    #     print(ip)
    sensitiveport = filtering_by_sensitive_port(network_line)
    # for port in sensitiveport:
    #     print(port)

if __name__ == "__main__":
    main()