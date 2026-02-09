from reader import read_network_file

def main():
    my_path = 'C:\\Users\\sendi\\PycharmProjects\\PythonProject1\\log_analyzer\\log_analyzer\\network_traffic.log'
    network_line = read_network_file(my_path)
    

if __name__ == "__main__":
    main()