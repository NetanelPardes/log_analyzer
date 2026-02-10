import reader
import checks
import reporter

def main():
    my_path = 'C:\\Users\\sendi\\PycharmProjects\\PythonProject1\\log_analyzer\\log_analyzer\\network_traffic.log'
    # network_line = reader.read_network_file(my_path)
    #
    # external_IP_addresses = checks.external_addresses(network_line)
    #
    # # for ip in external_IP_addresses:
    # #     print(ip)
    #
    # sensitiveport = checks.filtering_by_sensitive_port(network_line)
    #
    # # for port in sensitiveport:
    # #     print(port)
    #
    # greater_than_5000 = checks.filter_by_size(network_line)
    #
    # # for port in greater_than_5000:
    # #     print(port)
    #
    # tag_lines = checks.tag_traffic_by_size(network_line)
    #
    # # for port in tag_lines:
    # #     print(port)
    #
    # network_dict = reporter.Number_uses_network(network_line)
    # # print(network_dict)
    #
    # protocol_and_port = reporter.protocol_name_and_port_number(network_line)
    # # print(protocol_and_port)

if __name__ == "__main__":
    main()