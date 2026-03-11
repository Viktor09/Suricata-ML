import json
import subprocess
import os
import time

suricata_json = "arp_victims.json" 
rules_file = "/etc/suricata/rules/dynamic.rules"
base_id = 1000000
elapsed_time = 900

current_affected_ips = set()

def generate_suricata_rules():
    global current_affected_ips
    try:
        if not os.path.exists(suricata_json):
            return False

        with open(suricata_json, 'r') as f:
            data = json.load(f)

        json_timestamp = data.get("timestamp", 0)
        current_time = time.time()

        if (current_time - json_timestamp) < elapsed_time:
            new_affected_ips = set(data.get("affected_ips", []))
        else:
            new_affected_ips = set()

        if new_affected_ips == current_affected_ips:
            return False
        
        current_affected_ips = new_affected_ips

        rules = []
        for i, ip in enumerate(sorted(list(current_affected_ips))):
            current_sid = base_id + i
            rule = (f'alert ip {ip} any -> any any (msg:"Affected ip: {ip} ARP Spoofing Attack"; '
                    f'sid:{current_sid}; rev:1; threshold:type limit, track by_src, count 1, seconds 60;)')
            rules.append(rule)

        with open(rules_file, 'w') as f:
            f.write('\n'.join(rules))

        return True
        
    except Exception as e:
        print(f"Error: {e}")
        return False

if __name__ == "__main__":
    while True:
        changed = generate_suricata_rules()
        if changed:
            try:
                subprocess.run(['suricatasc', '-c', 'reload-rules'], check=True, capture_output=True)
            except:
                pass
        time.sleep(10)