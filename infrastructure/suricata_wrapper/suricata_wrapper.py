import json
import subprocess
import time
import os

alerts_json = os.environ.get("ALERTS_PATH", "/app/alerts/alerts.json")
rules_file = os.environ.get("RULES_FILE", "/etc/suricata/rules/dynamic.rules")

base_id = 1000000
rule_refresh_interval = 300

model_states = {}
model_rules = {}
model_timestamps = {}

def resolve_proto(protocol):
    if protocol is None:
        return "ip"
    proto = str(protocol).lower().strip()
    if not proto:
        return "ip"
    return proto


def build_rules(event, base_sid):
    attack_type = event.get("attack_type") or "UNKNOWN"
    src_ip = event.get("src_ip") or "any"
    protocol = event.get("protocol")

    if src_ip in ("unknown", "0.0.0.0", None, "any"):
        return []

    signature = (event["alert"]["signature"] if event.get("alert") and event["alert"].get("signature") else f"{attack_type} detected")

    dst_ip = event.get("dest_ip") or event.get("dst_ip")
    if isinstance(dst_ip, list):
        victims = [v for v in dst_ip if v and v not in ("unknown", "0.0.0.0")]
    elif dst_ip and dst_ip not in ("unknown", "0.0.0.0"):
        victims = [dst_ip]
    else:
        victims = []

    if not victims:
        return []

    proto = resolve_proto(protocol)

    rules = []
    for i, victim in enumerate(victims):
        sid = base_sid + i
        rule = (
            f'alert {proto} {src_ip} any -> {victim} any '
            f'(msg:"{signature}"; '
            f'threshold: type limit, track by_dst, count 1, seconds 10; '
            f'sid:{sid}; rev:1;)'
        )
        rules.append(rule)
    return rules


def write_rules():
    rules = []
    for model_name, rule_or_list in model_rules.items():
        if not rule_or_list:
            continue
        if isinstance(rule_or_list, list):
            rules.extend(rule_or_list)
        else:
            rules.append(rule_or_list)
    with open(rules_file, "w") as f:
        f.write("\n".join(rules) + "\n" if rules else "")
        f.flush()
        os.fsync(f.fileno())


def reload_suricata():
    subprocess.run(
        ["suricatasc", "-c", "reload-rules", "/var/run/suricata/suricata-command.socket"],
        check=True, capture_output=True, text=True
    )
    print(f"[{time.strftime('%H:%M:%S')}] Suricata rules reloaded.")

def process_events(events):
    changed = False
    for event in events:
        status = event.get("status", "clear")

        if status == "clear":
            continue

        if status == "attack":
            attack_type = event.get("attack_type") or event.get("event_type") or "UNKNOWN"
            src_ip = event.get("src_ip") or "any"

            if src_ip in ("unknown", "0.0.0.0", None, "any"):
                continue

            dst_ip = event.get("dest_ip") or event.get("dst_ip") or []
            if isinstance(dst_ip, list):
                victims_key = ",".join(sorted(v for v in dst_ip if v and v not in ("unknown", "0.0.0.0")))
            elif dst_ip and dst_ip not in ("unknown", "0.0.0.0"):
                victims_key = dst_ip
            else:
                victims_key = "any"

            if not victims_key or victims_key == "any":
                continue

            model_name = f"{attack_type}:{src_ip}:{victims_key}"
            base_sid = base_id + abs(hash(model_name)) % 900000
            rules = build_rules(event, base_sid)

            if not rules:
                continue

            if model_rules.get(model_name) != rules:
                model_states[model_name] = "attack"
                model_rules[model_name] = rules
                model_timestamps[model_name] = time.time()
                for rule in rules:
                    print(f"[{time.strftime('%H:%M:%S')}] [RULE] {model_name} | {rule}")
                changed = True
            else:
                model_timestamps[model_name] = time.time()

    return changed

def check_expired_rules():
    changed = False
    now = time.time()
    for model_name in list(model_timestamps.keys()):
        if now - model_timestamps[model_name] > rule_refresh_interval:
            print(f"[{time.strftime('%H:%M:%S')}] [EXPIRED] {model_name} — clearing rule")
            model_states[model_name] = "clear"
            model_rules[model_name] = None
            del model_timestamps[model_name]
            changed = True
    return changed

def read_new_events(last_pos):
    events = []

    with open(alerts_json, "r") as f:
        f.seek(last_pos)
        for line in f:
            line = line.strip()
            if not line:
                continue
            parsed = json.loads(line)
            if isinstance(parsed, dict):
                events.append(parsed)
        new_pos = f.tell()
  
    return events, new_pos

if __name__ == "__main__":
    last_pos = 0

    with open(alerts_json, "r") as f:
        f.seek(0, 2)
        last_pos = f.tell()
    

    print(f"[{time.strftime('%H:%M:%S')}] Suricata-Wrapper started...")

    while True:
        events, last_pos = read_new_events(last_pos)
        changed = process_events(events)
        changed |= check_expired_rules()

        if changed:
            write_rules()
            reload_suricata()

        time.sleep(1)
