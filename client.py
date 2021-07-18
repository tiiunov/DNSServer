import socket
import json


def main():
    udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    while True:
        host = "127.0.0.1"
        port = 53
        user_request = input()
        udp.sendto(user_request.encode(), (host, port))
        response = udp.recv(1488)
        record = json.loads(response.decode())
        print(f'{user_request.split()[1]} --- {user_request.split()[0]} --- {record["data"]}')


if __name__ == '__main__':
    main()
