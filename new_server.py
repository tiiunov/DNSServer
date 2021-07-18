import socket
import datetime
import jsonpickle
from scapy.layers.dns import *


class MyDNS:
    def __init__(self):
        self.cache = []
        with open("cache.txt", mode="r") as file:
            for record in file.readlines():
                self.cache.append(jsonpickle.decode(record))

    def load(self):
        types = {1: "A", 2: "NS", 12: "PTR", 28: "AAAA"}
        host = "127.0.0.1"
        port = 53
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.bind((host, port))
        s_req = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        while True:
            data, address = s.recvfrom(65535)
            request = DNS(_pkt=data)
            name = request.qd.qname.decode()
            rec_type = types[request.qd.qtype]
            current_time = datetime.datetime.now()
            current_cache = []
            for r in self.cache:
                if current_time < r["ttk"]:
                    current_cache.append(r)
            self.cache = current_cache
            record = self.search_in_cache(name, rec_type)
            if record:
                s.sendto(jsonpickle.encode(record).pkt, address)
            else:
                s_req.sendto(data, ("8.8.8.8", 53))
                response = s_req.recv(65535)
                out = DNS(_pkt=response)
                s.sendto(response, address)
                an_count = out.ancount - 1
                if out.an:
                    rcrd = self.make_rec(out.an, out)
                    self.cache.append(rcrd)
                    out = out.an
                    for _ in range(an_count):
                        rcrd = self.make_rec(out.payload, out)
                        self.cache.append(rcrd)
                        print(len(server.cache), rcrd["ttl"], rcrd["name"], rcrd["data"], sep=' ')
                        out = out.payload
            with open("cache.txt", mode="w") as file:
                for rec in self.cache:
                    file.write(jsonpickle.encode(rec) + "\n")

    def search_in_cache(self, name, rec_type):
        for rec in self.cache:
            if rec["name"] == name and rec["type"] == rec_type:
                return rec

    @staticmethod
    def make_rec(answer, pkt):
        types = {2: "NS", 1: "A", 12: "PTR", 28: "AAAA"}
        result = {"name": answer.rrname.decode(),
                  "type": types[answer.type],
                  "ttl": answer.ttl,
                  "pkt": pkt,
                  "ttk": datetime.datetime.now() + datetime.timedelta(seconds=answer.ttl)}
        data = answer.rdata
        if type(data) is not str:
            data = data.decode()
        result["data"] = data
        return result


if __name__ == '__main__':
    server = MyDNS()
    server.load()
