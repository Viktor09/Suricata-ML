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

MAX_CAPTURE_SECONDS = 15
TARGET_CAPTURE_MB = 200
CHECK_INTERVAL = 0.25
CICFLOW_TIMEOUT = 90
COOLDOWN_SECONDS = 10
WINDOW_SIZE = 24
ATTACK_RATIO_THRESHOLD = 0.60

MIN_CAPTURE_SECONDS = 10
MAX_CAPTURE_SECONDS = 15
TARGET_CAPTURE_MB = 200

CLASS_CONFIDENCE_THRESHOLDS = {
    1: 0.30,
    2: 0.30,
    3: 0.50,
}

REFLECTION_SERVICE_PORTS = {
    53,    # DNS
    69,    # TFTP
    111,   # Portmap
    123,   # NTP
    137,   # NetBIOS
    161,   # SNMP
    389,   # LDAP
    1434,  # MSSQL
}


def log(msg):
    print(f"[{time.strftime('%H:%M:%S')}] {msg}", flush=True)


def mb(path):
    if os.path.exists(path):
        return os.path.getsize(path) // 1024 // 1024
    else:
        return 0


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
    renamed = {c: COLUMN_MAPPING[c] for c in df.columns if c in COLUMN_MAPPING}
    return df.rename(columns=renamed)


def load_ddos_model(model_dir):
    model = joblib.load(os.path.join(model_dir, "ddos_model.joblib"))

    if hasattr(model, "verbose"):
        model.verbose = 0

    with open(os.path.join(model_dir, "metadata.json"), "r", encoding="utf-8") as f:
        metadata = json.load(f)

    model_features = metadata["feature_columns"]
    class_names = {i: name for i, name in enumerate(metadata["class_names"])}

    return model, model_features, class_names


def start_tcpdump(interface, live_pcap):
    cmd = ["sudo", "tcpdump", "-q", "-n", "-i", interface, "-w", live_pcap, "-U"]

    return subprocess.Popen(
        cmd,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        stdin=subprocess.DEVNULL,
        start_new_session=True
    )


def wait_capture_window(tcpdump_process, live_pcap):
    start = time.time()

    while tcpdump_process.poll() is None:
        elapsed = time.time() - start

        if mb(live_pcap) >= TARGET_CAPTURE_MB and elapsed >= MIN_CAPTURE_SECONDS:
            return "ready"

        if elapsed >= MAX_CAPTURE_SECONDS:
            if os.path.exists(live_pcap):
                size_bytes = os.path.getsize(live_pcap)
            else:
                size_bytes = 0

            if size_bytes > 0:
                return "ready"
            else:
                return "too_small"

        time.sleep(CHECK_INTERVAL)

    return "tcpdump_dead"


def move_pcap_to_cicflow(live_pcap, pcap_file, dir_pcap):
    clean_directory(dir_pcap)

    if not os.path.exists(live_pcap):
        return False

    if os.path.getsize(live_pcap) == 0:
        safe_remove(live_pcap)
        return False

    os.replace(live_pcap, pcap_file)
    return True


def run_cicflowmeter(dir_cicflow):
    result = subprocess.run(
        ["./gradlew", "exeCMD"],
        cwd=dir_cicflow,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        timeout=CICFLOW_TIMEOUT
    )

    return result.returncode == 0


def read_flows(dir_output):
    csv_files = []

    for filename in os.listdir(dir_output):
        if filename.endswith(".csv"):
            csv_files.append(os.path.join(dir_output, filename))

    if not csv_files:
        return pd.DataFrame(), pd.DataFrame()

    latest_csv = max(csv_files, key=os.path.getmtime)

    try:
        df = pd.read_csv(latest_csv)
    except Exception as e:
        log(f"[!] Could not read CSV: {e}")
        return pd.DataFrame(), pd.DataFrame()

    if df.empty:
        return pd.DataFrame(), pd.DataFrame()

    df = normalize_columns(df)

    existing_ip_cols = []
    for col in IP_COLS:
        if col in df.columns:
            existing_ip_cols.append(col)

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


def is_in_cooldown(key, cooldowns):
    if key in cooldowns and time.time() - cooldowns[key] < COOLDOWN_SECONDS:
        return True
    return False


def set_cooldown(key, cooldowns):
    if key:
        cooldowns[key] = time.time()


def cleanup_expired_cooldowns(cooldowns):
    now = time.time()

    for key in list(cooldowns.keys()):
        if now - cooldowns[key] >= COOLDOWN_SECONDS:
            del cooldowns[key]


def decide_window(window):
    if len(window) < WINDOW_SIZE:
        return None

    df_window = pd.DataFrame(list(window))

    if "pred" not in df_window.columns or "conf" not in df_window.columns:
        return False, 0.0, 0.0, 0, 0.0

    df_window["pred"] = pd.to_numeric(
        df_window["pred"],
        errors="coerce"
    ).fillna(0).astype(int)

    df_window["conf"] = pd.to_numeric(
        df_window["conf"],
        errors="coerce"
    ).fillna(0.0)

    attack_flows = df_window[df_window["pred"] != 0]
    attack_ratio = len(attack_flows) / len(df_window)

    if attack_flows.empty:
        return False, attack_ratio, 0.0, 0, 0.0

    main_attack = int(attack_flows["pred"].mode().iloc[0])
    main_attack_flows = df_window[df_window["pred"] == main_attack]

    main_ratio = len(main_attack_flows) / len(df_window)
    avg_conf = main_attack_flows["conf"].mean()

    required_conf = CLASS_CONFIDENCE_THRESHOLDS.get(main_attack, 0.50)

    is_attack = False
    if main_ratio >= ATTACK_RATIO_THRESHOLD and avg_conf >= required_conf:
        is_attack = True

    return is_attack, float(attack_ratio), float(avg_conf), main_attack, float(main_ratio)


def get_main_attack_flow(window, main_attack, attack_name):
    if not window:
        return None, None, None, None

    df_window = pd.DataFrame(list(window))

    needed_cols = ["pred", "src", "dst", "src_port", "dst_port"]
    for col in needed_cols:
        if col not in df_window.columns:
            return None, None, None, None

    df_window["pred"] = pd.to_numeric(
        df_window["pred"],
        errors="coerce"
    ).fillna(0).astype(int)

    df_window["src_port"] = pd.to_numeric(
        df_window["src_port"],
        errors="coerce"
    )

    df_window["dst_port"] = pd.to_numeric(
        df_window["dst_port"],
        errors="coerce"
    )

    attack_flows = df_window[
        (df_window["pred"] == int(main_attack)) &
        (df_window["src"].notna()) &
        (df_window["dst"].notna()) &
        (df_window["src_port"].notna()) &
        (df_window["dst_port"].notna())
    ]

    if attack_flows.empty:
        return None, None, None, None

    grouped_flows = (
        attack_flows
        .groupby(["src", "src_port", "dst", "dst_port"])
        .size()
        .reset_index(name="count")
        .sort_values("count", ascending=False)
    )

    if grouped_flows.empty:
        return None, None, None, None

    main_flow = grouped_flows.iloc[0]

    src_ip = main_flow["src"]
    src_port = int(main_flow["src_port"])
    dst_ip = main_flow["dst"]
    dst_port = int(main_flow["dst_port"])

    if attack_name == "DrDoS":
        src_is_service = src_port in REFLECTION_SERVICE_PORTS
        dst_is_service = dst_port in REFLECTION_SERVICE_PORTS

        if src_is_service and not dst_is_service:
            return src_ip, src_port, dst_ip, dst_port

        if dst_is_service and not src_is_service:
            return dst_ip, dst_port, src_ip, src_port

    return src_ip, src_port, dst_ip, dst_port


def summarize_predictions(preds, confs, class_names):
    df_preds = pd.DataFrame({
        "pred": preds,
        "conf": confs
    })

    if df_preds.empty:
        return "", "", Counter()

    df_preds["pred"] = pd.to_numeric(
        df_preds["pred"],
        errors="coerce"
    ).fillna(0).astype(int)

    df_preds["conf"] = pd.to_numeric(
        df_preds["conf"],
        errors="coerce"
    ).fillna(0.0)

    pred_counts = df_preds["pred"].value_counts().sort_index()
    pred_counter = Counter(pred_counts.to_dict())

    pred_parts = []
    for class_id, count in pred_counts.items():
        class_name = class_names.get(int(class_id), str(class_id))
        pred_parts.append(f"{class_name}={int(count)}")

    pred_summary = " ".join(pred_parts)

    avg_conf_by_class = df_preds.groupby("pred")["conf"].mean().sort_index()

    conf_parts = []
    for class_id, avg_conf in avg_conf_by_class.items():
        class_name = class_names.get(int(class_id), str(class_id))
        conf_parts.append(f"{class_name}_conf={avg_conf:.2f}")

    conf_summary = " ".join(conf_parts)

    return pred_summary, conf_summary, pred_counter


def process_flows(flows, df_ips, model, model_features, class_names, window, cooldowns, batch):
    X = prepare_for_model(flows, model_features)

    if X is None or X.empty:
        log(f"[INFO] batch={batch} | Nu există flow-uri valide pentru model")
        return

    predictions = model.predict(X)

    if hasattr(model, "predict_proba"):
        probabilities = model.predict_proba(X)
        confidences = np.max(probabilities, axis=1)
    else:
        confidences = np.ones(len(predictions))

    pred_summary, conf_summary, _ = summarize_predictions(
        predictions,
        confidences,
        class_names
    )

    for index, prediction in enumerate(predictions):
        flow_info = {
            "pred": int(prediction),
            "conf": float(confidences[index]),
            "src": None,
            "dst": None,
            "src_port": None,
            "dst_port": None,
            "protocol": None
        }

        if not df_ips.empty and index < len(df_ips):
            ip_row = df_ips.iloc[index]

            flow_info["src"] = ip_row.get("Src IP")
            flow_info["dst"] = ip_row.get("Dst IP")
            flow_info["src_port"] = ip_row.get("Src Port")
            flow_info["dst_port"] = ip_row.get("Dst Port")
            flow_info["protocol"] = ip_row.get("Protocol")

        window.append(flow_info)

    decision = decide_window(window)

    if decision is None:
        log(
            f"[INFO] batch={batch} | flows={len(flows)} | "
            f"window={len(window)}/{WINDOW_SIZE} | "
            f"preds={pred_summary} | {conf_summary}"
        )
        return

    is_attack, attack_ratio, avg_conf, main_attack, main_ratio = decision
    attack_name = class_names.get(int(main_attack), f"UNKNOWN_{main_attack}")

    src_ip, src_port, dst_ip, dst_port = get_main_attack_flow(
        window,
        main_attack,
        attack_name
    )

    if is_attack:
        cooldown_key = f"{dst_ip}:{dst_port}" if dst_ip and dst_port else "global"

        if is_in_cooldown(cooldown_key, cooldowns):
            if attack_name == "DrDoS":
                log(
                    f"[SKIP] cooldown | "
                    f"type={attack_name} | "
                    f"reflector={src_ip or '?'}:{src_port or '?'} | "
                    f"victim={dst_ip or '?'}:{dst_port or '?'}"
                )
            else:
                log(
                    f"[SKIP] cooldown | "
                    f"type={attack_name} | "
                    f"source={src_ip or '?'}:{src_port or '?'} | "
                    f"target={dst_ip or '?'}:{dst_port or '?'}"
                )
            return

        set_cooldown(cooldown_key, cooldowns)

        if attack_name == "DrDoS":
            log(
                f"[ALERT] {attack_name} | "
                f"probability={avg_conf * 100:.1f}% | "
                f"reflector={src_ip or '?'}:{src_port or '?'} | "
                f"victim={dst_ip or '?'}:{dst_port or '?'}"
            )
        else:
            log(
                f"[ALERT] {attack_name} | "
                f"probability={avg_conf * 100:.1f}% | "
                f"source={src_ip or '?'}:{src_port or '?'} | "
                f"target={dst_ip or '?'}:{dst_port or '?'}"
            )

        return

    log(
        f"[OK] traffic looks normal | "
        f"main={attack_name} | "
        f"probability={avg_conf * 100:.1f}%"
    )


if __name__ == "__main__":
    dir_pcap = "/home/ubuntu/pcaps"
    dir_output = "/home/ubuntu/output"
    dir_cicflow = "/home/ubuntu/CICFlowMeter"
    model_dir = "/home/ubuntu/model_ddos"
    live_pcap = "/home/ubuntu/live_capture.pcap"
    pcap_file = os.path.join(dir_pcap, "capture.pcap")
    interface = "virbr-labs"

    batch = 0
    tcpdump_process = None
    cooldowns = {}
    window = deque(maxlen=WINDOW_SIZE)

    log("Loading DDoS model...")
    model, model_features, class_names = load_ddos_model(model_dir)
    log(f"Model loaded | features={len(model_features)} | classes={list(class_names.values())}")

    os.makedirs(dir_pcap, exist_ok=True)
    os.makedirs(dir_output, exist_ok=True)
    free_space(live_pcap, dir_pcap, dir_output)

    log("Starting DDoS detection...")

    try:
        while True:
            batch += 1
            cleanup_expired_cooldowns(cooldowns)
            safe_remove(live_pcap)

            log(f"Capturing traffic | batch={batch}")

            tcpdump_process = start_tcpdump(interface, live_pcap)
            capture_status = wait_capture_window(tcpdump_process, live_pcap)
            stop_process(tcpdump_process)
            tcpdump_process = None

            if capture_status == "tcpdump_dead":
                log("Tcpdump stopped unexpectedly!")
                safe_remove(live_pcap)
                time.sleep(1)
                continue

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

            try:
                ok = run_cicflowmeter(dir_cicflow)
            except subprocess.TimeoutExpired:
                log("CICFlowMeter timeout!")
                free_space(live_pcap, dir_pcap, dir_output)
                time.sleep(1)
                continue
            except Exception:
                log("CICFlowMeter failed!")
                free_space(live_pcap, dir_pcap, dir_output)
                time.sleep(1)
                continue

            if not ok:
                log("CICFlowMeter error!")
                free_space(live_pcap, dir_pcap, dir_output)
                time.sleep(1)
                continue

            flows, df_ips = read_flows(dir_output)

            if flows.empty:
                log("No flows extracted!")
                clean_directory(dir_pcap)
                clean_directory(dir_output)
                time.sleep(1)
                continue

            process_flows(
                flows=flows,
                df_ips=df_ips,
                model=model,
                model_features=model_features,
                class_names=class_names,
                window=window,
                cooldowns=cooldowns,
                batch=batch
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
        log("Stopped.")