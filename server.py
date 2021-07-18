import socket
import datetime
import jsonpickle
from scapy.layers.dns import *


class MyDNS:
    def __init__(self):
        self.cache = []
        with open("cache.txt", mode="r") as f:
            for record in f.readlines():
                self.cache.append(jsonpickle.decode(record))

    def load(self):
        host = "127.0.0.1"
        port = 53
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.bind((host, port))
        main_s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        while True:
            data, address = s.recvfrom(1488)
            data = data.decode()
            rec_type, name = data.split()
            current_time = datetime.datetime.now()
            current_cache = []
            for r in self.cache:
                if current_time < r["ttk"]:
                    current_cache.append(r)
            self.cache = current_cache
            rec = self.search_in_cache(name, rec_type)
            if rec:
                s.sendto(jsonpickle.encode(rec).decode(), address)
            else:
                if rec_type == "PTR":
                    split_name = name.split('.')
                    split_name.reverse()
                    name = '.'.join(split_name) + ".in-addr.arpa"
                dns = DNSQR(qname=name, qtype=rec_type)
                package = DNS(qd=dns).build()
                main_s.sendto(package, ("8.8.8.8", 53))
                response = main_s.recv(1488)
                out = DNS(_pkt=response)
                s.sendto(jsonpickle.encode(self.make_rec(out.an)).encode(), address)
                an_count = out.ancount - 1
                rec = self.make_rec(out.an)
                self.cache.append(rec)
                out = out.an
                for _ in range(an_count):
                    rec = self.make_rec(out.payload)
                    self.cache.append(rec)
                    out = out.payload
            with open("cache.txt", mode="w") as file:
                for rec in self.cache:
                    file.write(jsonpickle.encode(rec) + "\n")

    def search_in_cache(self, name, rec_type):
        for rec in self.cache:
            if rec["name"] == name and rec["type"] == rec_type:
                return rec

    @staticmethod
    def make_rec(answer):
        types = {2: "NS", 1: "A", 12: "PTR", 28: "AAAA"}
        result = {"name": answer.rrname.decode(),
                  "type": types[answer.type],
                  "ttl": answer.ttl,
                  "ttk": datetime.datetime.now() + datetime.timedelta(seconds=answer.ttl)}
        data = answer.rdata
        if type(data) is not str:
            data = data.decode()
        result["data"] = data
        return result


if __name__ == '__main__':
    server = MyDNS()
    server.load()
