import subprocess
import pandas as pd
import os
import time
import shutil
import json
import joblib
import numpy as np
from collections import deque, Counter

COLUMN_MAPPING = {
    "Total Fwd Packet": "Total Fwd Packets",
    "Total Bwd packets": "Total Backward Packets",
    "Total Length of Fwd Packet": "Fwd Packets Length Total",
    "FWD Init Win Bytes": "Init Fwd Win Bytes",
    "Bwd Init Win Bytes": "Init Bwd Win Bytes",
    "CWR Flag Count": "CWE Flag Count",
    "Fwd Act Data Pkts": "Fwd Act Data Packets",
}

IP_COLS = ["Src IP", "Dst IP", "Src Port", "Dst Port", "Protocol"]

MIN_CAPTURE_SECONDS = 35
MAX_CAPTURE_SECONDS = 40
TARGET_CAPTURE_MB = 200
CHECK_INTERVAL = 1
CICFLOW_TIMEOUT = 180
COOLDOWN_SECONDS = 10
WINDOW_SIZE = 2
ATTACK_RATIO_THRESHOLD = 0.50

CLASS_CONFIDENCE_THRESHOLDS = {1: 0.50, 2: 0.30, 3: 0.55}
REFLECTION_SERVICE_PORTS = {53, 69, 111, 123, 137, 161, 389, 1434}
NUMBER_TO_NAME_PROTO = {6: "tcp", 17: "udp", 1: "icmp"}

alerts_json = os.environ.get("ALERTS_PATH", "/app/alerts/alerts.json")

def write_alert(event_type, attack_name, src_ip, src_port, dst_ip, dst_port, protocol=None):
    event = {
        "status": "attack",
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S"),
        "event_type": event_type,
        "attack_type": attack_name,
        "protocol": protocol,
        "src_ip": str(src_ip) if src_ip is not None else None,
        "src_port": int(src_port) if src_port is not None and not pd.isna(src_port) else None,
        "dst_ip": str(dst_ip) if dst_ip is not None else None,
        "dst_port": int(dst_port) if dst_port is not None and not pd.isna(dst_port) else None,
        "alert": {
            "signature": f"DDoS attack detected: {attack_name}",
            "severity": 2
        }
    }

    with open(alerts_json, "a") as f:
        f.write(json.dumps(event) + "\n")


def write_clear():
    event = {
        "status": "clear",
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S"),
        "event_type": "clear",
        "src_ip": None,
        "src_port": None,
        "dst_ip": None,
        "dst_port": None,
        "alert": {}
    }
    with open(alerts_json, "a") as f:
        f.write(json.dumps(event) + "\n")

def log(msg):
    print(f"[{time.strftime('%H:%M:%S')}] {msg}", flush=True)

def safe_remove(path):
    try:
        if os.path.exists(path):
            os.remove(path)
            return True
    except Exception:
        pass
    return False

def clean_directory(dir_path):
    os.makedirs(dir_path, exist_ok=True)
    for filename in os.listdir(dir_path):
        path = os.path.join(dir_path, filename)
        try:
            if os.path.isfile(path) or os.path.islink(path):
                os.remove(path)
            elif os.path.isdir(path):
                shutil.rmtree(path)
        except Exception:
            pass

def free_space(live_pcap, dir_pcap, dir_output):
    safe_remove(live_pcap)
    clean_directory(dir_pcap)
    clean_directory(dir_output)

def stop_process(process):
    if process and process.poll() is None:
        try:
            process.terminate()
            process.wait(timeout=3)
        except Exception:
            process.kill()
            process.wait()

def normalize_columns(df):
    df.columns = [str(c).strip() for c in df.columns]
    return df.rename(columns={c: COLUMN_MAPPING[c] for c in df.columns if c in COLUMN_MAPPING})

def load_ddos_model(model_dir):
    model_path = os.path.join(model_dir, "ddos_model.joblib")
    model = joblib.load(model_path)
    with open(os.path.join(model_dir, "metadata.json"), "r", encoding="utf-8") as f:
        metadata = json.load(f)
    class_names = {i: name for i, name in enumerate(metadata["class_names"])}
    return model, metadata["feature_columns"], class_names

def start_tcpdump(interface, live_pcap):
    return subprocess.Popen(
        ["tcpdump", "-q", "-n", "-i", interface, "-w", live_pcap, "-U"],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        stdin=subprocess.DEVNULL, start_new_session=True
    )

def wait_capture_window(tcpdump_process, live_pcap):
    start = time.time()
    while tcpdump_process.poll() is None:
        elapsed = time.time() - start
        if not os.path.exists(live_pcap):
            time.sleep(CHECK_INTERVAL)
            continue
        live_pcap_size = os.path.getsize(live_pcap) // 1024 // 1024
        if live_pcap_size >= TARGET_CAPTURE_MB and elapsed >= MIN_CAPTURE_SECONDS:
            return "ready"
        if elapsed >= MAX_CAPTURE_SECONDS:
            if os.path.getsize(live_pcap) > 0:
                return "ready"
            return "too_small"
        time.sleep(CHECK_INTERVAL)
    return "tcpdump_dead"


def move_pcap_to_cicflow(live_pcap, pcap_file, dir_pcap):
    clean_directory(dir_pcap)
    if not os.path.exists(live_pcap) or os.path.getsize(live_pcap) == 0:
        safe_remove(live_pcap)
        return False
    os.replace(live_pcap, pcap_file)
    return True


def run_cicflowmeter(dir_cicflow):
    result = subprocess.run(
        ["./gradlew", "exeCMD"], cwd=dir_cicflow,
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        timeout=CICFLOW_TIMEOUT
    )
    return result.returncode == 0


def read_flows(dir_output):
    csv_files = [os.path.join(dir_output, filename) for filename in os.listdir(dir_output) if filename.endswith(".csv")]

    if not csv_files:
        return pd.DataFrame(), pd.DataFrame()

    csv_file = csv_files[0]
    df = pd.read_csv(csv_file)
    df = normalize_columns(df)

    existing_ip_cols = [col for col in IP_COLS if col in df.columns]
    if existing_ip_cols:
        df_ips = df[existing_ip_cols].copy()
    else:
        df_ips = pd.DataFrame()

    return df.reset_index(drop=True), df_ips.reset_index(drop=True)


def prepare_for_model(df, model_features):
    df = normalize_columns(df.copy())
    missing = [c for c in model_features if c not in df.columns]
    if missing:
        return None
    X = df[model_features].copy()
    for col in X.columns:
        X[col] = pd.to_numeric(X[col], errors="coerce")
    X.replace([np.inf, -np.inf], np.nan, inplace=True)
    X.fillna(0, inplace=True)
    return X


def analyze_window(window, class_names):
    if len(window) < WINDOW_SIZE:
        return None
    df = pd.DataFrame(list(window))
    if "pred" not in df.columns or "conf" not in df.columns:
        return False, 0.0, 0.0, 0, 0.0, None, None, None, None

    df["pred"] = pd.to_numeric(df["pred"], errors="coerce").fillna(0).astype(int)
    df["conf"] = pd.to_numeric(df["conf"], errors="coerce").fillna(0.0)
    df["src_port"] = pd.to_numeric(df["src_port"], errors="coerce")
    df["dst_port"] = pd.to_numeric(df["dst_port"], errors="coerce")

    total = len(df)
    attack_flows = df[df["pred"] != 0]
    attack_ratio = len(attack_flows) / total

    if attack_flows.empty:
        return False, attack_ratio, 0.0, 0, 0.0, None, None, None, None

    dominant_attack = int(attack_flows["pred"].mode().iloc[0])
    dominant_flows = df[df["pred"] == dominant_attack]
    dominant_ratio = len(dominant_flows) / total
    avg_conf = dominant_flows["conf"].mean()

    required_conf = CLASS_CONFIDENCE_THRESHOLDS.get(dominant_attack, 0.50)
    is_attack = False
    if dominant_ratio >= ATTACK_RATIO_THRESHOLD and avg_conf >= required_conf:
      is_attack = True

    src_ip = None
    src_port = None
    dst_ip = None
    dst_port = None

    required_columns = ["src", "dst", "src_port", "dst_port"]
    has_required_columns = all(col in df.columns for col in required_columns)

    if has_required_columns:
        valid_flows = dominant_flows.dropna(subset=["src", "dst", "src_port", "dst_port"])

        if not valid_flows.empty:
            flow_counts = (valid_flows.groupby(["src", "src_port", "dst", "dst_port"]).size().reset_index(name="count").sort_values("count", ascending=False))
            most_common_flow = flow_counts.iloc[0]

            src_ip = most_common_flow["src"]
            src_port = int(most_common_flow["src_port"])

            dst_ip = most_common_flow["dst"]
            dst_port = int(most_common_flow["dst_port"])

            attack_name = class_names.get(dominant_attack, "")

            is_drdos = attack_name == "DrDoS"
            dst_is_reflector_service = dst_port in REFLECTION_SERVICE_PORTS
            src_is_not_reflector_service = src_port not in REFLECTION_SERVICE_PORTS

            if is_drdos and dst_is_reflector_service and src_is_not_reflector_service:
                src_ip, dst_ip = dst_ip, src_ip
                src_port, dst_port = dst_port, src_port

    return is_attack, float(attack_ratio), float(avg_conf), dominant_attack, float(dominant_ratio), src_ip, src_port, dst_ip, dst_port


def get_dominant_protocol(df_ips):
    if df_ips.empty or "Protocol" not in df_ips.columns:
        return None

    proto_raw = df_ips["Protocol"].dropna().mode()
    if proto_raw.empty:
        return None

    val = proto_raw.iloc[0]

    return NUMBER_TO_NAME_PROTO.get(int(val), str(val).lower())

def process_flows(flows, df_ips, model, model_features, class_names, window, cooldowns, batch):
    X = prepare_for_model(flows, model_features)
    if X is None or X.empty:
        log(f"[INFO] batch={batch} | No available flows!")
        return

    predictions = model.predict(X)
    confidences = (
        np.max(model.predict_proba(X), axis=1)
        if hasattr(model, "predict_proba")
        else np.ones(len(predictions))
    )

    for index, prediction in enumerate(predictions):
        flow_info = {
            "pred": int(prediction), "conf": float(confidences[index]),
            "src": None, "dst": None,
            "src_port": None, "dst_port": None, "protocol": None
        }
        if not df_ips.empty and index < len(df_ips):
            ip_row = df_ips.iloc[index]
            flow_info["src"] = ip_row.get("Src IP")
            flow_info["dst"] = ip_row.get("Dst IP")
            flow_info["src_port"] = ip_row.get("Src Port")
            flow_info["dst_port"] = ip_row.get("Dst Port")
            flow_info["protocol"] = ip_row.get("Protocol")
        window.append(flow_info)

    decision = analyze_window(window, class_names)
    if decision is None:
        log(f"[INFO] batch={batch} | flows={len(flows)} | window={len(window)}/{WINDOW_SIZE}")
        return

    is_attack, attack_ratio, avg_conf, dominant_attack, dominant_ratio, src_ip, src_port, dst_ip, dst_port = decision
    attack_name = class_names.get(int(dominant_attack), f"UNKNOWN_{dominant_attack}")

    if is_attack:
        protocol = get_dominant_protocol(df_ips)
        write_alert("alert", attack_name, src_ip, src_port, dst_ip, dst_port, protocol=protocol)

        if attack_name == "DrDoS":
            log(f"[ALERT] {attack_name} | probability={avg_conf * 100:.1f}% | reflector={src_ip or '?'}:{src_port or '?'} | victim={dst_ip or '?'}:{dst_port or '?'}")
        else:
            log(f"[ALERT] {attack_name} | probability={avg_conf * 100:.1f}% | source={src_ip or '?'}:{src_port or '?'} | target={dst_ip or '?'}:{dst_port or '?'}")
        return

    write_clear()
    log(f"[NORMAL] traffic looks normal | main={attack_name} | probability={avg_conf * 100:.1f}%")


if __name__ == "__main__":
    dir_pcap = os.environ.get("PCAP_DIR", "/app/pcaps")
    dir_output = os.environ.get("OUTPUT_DIR", "/app/output")
    dir_cicflow = os.environ.get("CICFLOW_DIR", "/app/CICFlowMeter")
    model_dir = os.environ.get("MODEL_DIR", "/app/model_ddos")
    live_pcap = os.environ.get("LIVE_PCAP", "/app/live_capture.pcap")
    pcap_file = os.path.join(dir_pcap, "capture.pcap")
    interface = "virbr-labs"

    batch = 0
    tcpdump_process = None
    cooldowns = {}
    window = deque(maxlen=WINDOW_SIZE)

    log("Loading DDoS model...")
    model, model_features, class_names = load_ddos_model(model_dir)

    os.makedirs(dir_pcap, exist_ok=True)
    os.makedirs(dir_output, exist_ok=True)
    free_space(live_pcap, dir_pcap, dir_output)
    log("Starting DDoS detection...")

    try:
        while True:
            batch += 1
            safe_remove(live_pcap)

            tcpdump_process = start_tcpdump(interface, live_pcap)
            capture_status = wait_capture_window(tcpdump_process, live_pcap)
            stop_process(tcpdump_process)
            tcpdump_process = None

            if capture_status == "too_small":
                log("Not enough traffic!")
                safe_remove(live_pcap)
                time.sleep(1)
                continue

            if not move_pcap_to_cicflow(live_pcap, pcap_file, dir_pcap):
                log("Could not move pcap!")
                free_space(live_pcap, dir_pcap, dir_output)
                time.sleep(1)
                continue

            clean_directory(dir_output)

            run_cicflowmeter(dir_cicflow)

            flows, df_ips = read_flows(dir_output)
            if flows.empty:
                log("No flows extracted!")
                clean_directory(dir_pcap)
                clean_directory(dir_output)
                time.sleep(1)
                continue

            process_flows(
                flows=flows, df_ips=df_ips, model=model,
                model_features=model_features, class_names=class_names,
                window=window, cooldowns=cooldowns, batch=batch
            )

            clean_directory(dir_pcap)
            clean_directory(dir_output)
            time.sleep(1)

    except KeyboardInterrupt:
        log("Stopping...")
        if tcpdump_process is not None:
            stop_process(tcpdump_process)
        safe_remove(live_pcap)
        clean_directory(dir_pcap)
        clean_directory(dir_output)
