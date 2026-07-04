import subprocess
import os
import pandas as pd
import numpy as np
import torch
import torch.nn as nn
import math
import pickle
import sys
import json
import time
from collections import deque

suricata_json = os.environ.get("ALERTS_PATH", "alerts.json")

def log(msg):
    print(f"[{time.strftime('%H:%M:%S')}] {msg}", flush=True)

class PositionalEncoding(nn.Module):
    def __init__(self, d_model: int, dropout: float = 0.1, max_length: int = 50):
        super().__init__()
        self.dropout = nn.Dropout(p=dropout)
        pe = torch.zeros(max_length, d_model)
        k = torch.arange(0, max_length).unsqueeze(1)
        div_term = torch.exp(torch.arange(0, d_model, 2) * -(math.log(10000.0) / d_model))
        pe[:, 0::2] = torch.sin(k * div_term)
        pe[:, 1::2] = torch.cos(k * div_term)
        pe = pe.unsqueeze(0)
        self.register_buffer("pe", pe)

    def forward(self, x):
        x = x + self.pe[:, : x.size(1)].requires_grad_(False)
        return self.dropout(x)

class ARPSpoofingModel(nn.Module):
    def __init__(self, static_dim=4, dynamic_dim=7, embed_dim=32):
        super(ARPSpoofingModel, self).__init__()
        self.embedding = nn.Linear(static_dim, embed_dim)
        self.pos_encoder = PositionalEncoding(embed_dim)
        encoder_layer = nn.TransformerEncoderLayer(d_model=embed_dim, nhead=4, dim_feedforward=128, dropout=0.3, batch_first=True, activation='gelu')
        self.transformer = nn.TransformerEncoder(encoder_layer, num_layers=1)
        self.dynamic_projection = nn.Sequential(nn.Linear(dynamic_dim, embed_dim), nn.GELU())
        self.classifier = nn.Sequential(nn.Linear(embed_dim * 2, 32), nn.GELU(), nn.Dropout(0.3), nn.Linear(32, 1))

    def forward(self, x_static, x_dynamic):
        seq_features = self.embedding(x_static)
        seq_features = self.pos_encoder(seq_features)
        seq_out = self.transformer(seq_features)
        seq_representation = seq_out.mean(dim=1)
        dyn_representation = self.dynamic_projection(x_dynamic)
        combined = torch.cat([seq_representation, dyn_representation], dim=1)
        return self.classifier(combined)


def load_model(model_name):
    with open(model_name, "rb") as f:
        deploy_data = pickle.load(f)

    model = deploy_data["model"]
    scaler_s = deploy_data["scaler_s"]
    scaler_d = deploy_data["scaler_d"]
    
    if torch.cuda.is_available():
        device = "cuda"
    else:
        device = "cpu"

    model.to(device)
    model.eval()
    
    log(f"Model loaded on {device}.")
    
    return device, scaler_s, scaler_d, model

def clear_json():
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
    with open(suricata_json, "a") as f:
        f.write(json.dumps(event) + "\n")

def get_ip_by_mac(mac, real_ip_mac_map):
    for ip, known_mac in real_ip_mac_map.items():
        if known_mac == mac:
            return ip
    return "unknown"

def update_baseline(df_window, real_ip_mac_map, attack_active):
    for _, row in df_window.iterrows():
        ip = row["arp_src_ip"]
        mac = row["arp_src_mac"]
        if not ip or not mac:
            continue
        if ip not in real_ip_mac_map and not attack_active:
            real_ip_mac_map[ip] = mac

def update_mac_history(df_window, mac_seen_ips):
    for _, row in df_window.iterrows():
        mac = row.get("arp_src_mac")
        ip = row.get("arp_src_ip")
        if mac and ip:
            if mac not in mac_seen_ips:
                mac_seen_ips[mac] = set()
            mac_seen_ips[mac].add(ip)

def calculate_dynamic_features_global(scenario_window_df, real_ip_mac_map, mac_seen_ips, delta=0.1):
    features = {}
    victim_ips = set()
    attackers = {}

    n_requests = (scenario_window_df["arp_code"] == 1).sum()
    n_replies = (scenario_window_df["arp_code"] == 2).sum()

    if n_requests > 0:
        features["RRR"] = min(n_replies / n_requests, 10.0)
    else:
        features["RRR"] = float(n_replies)

    requested_ips = set(scenario_window_df[scenario_window_df['arp_code'] == 1]['arp_dst_ip'])
    orphan_replies = 0
    for _, row in scenario_window_df[scenario_window_df['arp_code'] == 2].iterrows():
        src_ip = row["arp_src_ip"]
        src_mac = row["arp_src_mac"]

        if not src_ip or not src_mac:
            continue

        if src_ip not in requested_ips:
            orphan_replies += 1

        if src_ip in real_ip_mac_map and src_mac != real_ip_mac_map[src_ip]:
            victim_ips.add(src_ip)
            if src_mac not in attackers:
                attacker_ip = get_ip_by_mac(src_mac, real_ip_mac_map)

                if attacker_ip == "unknown":
                    attacker_rows = scenario_window_df[
                        scenario_window_df["arp_src_mac"] == src_mac]["arp_src_ip"].unique()
                    for candidate in attacker_rows:
                        if candidate and candidate not in real_ip_mac_map:
                            attacker_ip = candidate
                            break

                if attacker_ip == "unknown" and src_mac in mac_seen_ips:
                    for candidate in mac_seen_ips[src_mac]:
                        if candidate and candidate not in real_ip_mac_map:
                            attacker_ip = candidate
                            break

                attackers[src_mac] = {
                    "attacker_ip": attacker_ip,
                    "attacker_mac": src_mac,
                    "victim_ips": set()
                }

            attackers[src_mac]["victim_ips"].add(src_ip)

    features["URR"] = orphan_replies / (n_replies + 1e-9)

    timedeltas = scenario_window_df["timedelta"]
    features["volatility"] = (timedeltas < delta).sum() / len(scenario_window_df)
    features["dt_cv"] = timedeltas.std() / (timedeltas.mean() + 1e-9)

    ip_mac_map = scenario_window_df.groupby("arp_src_ip")["arp_src_mac"].nunique()
    features["max_MD_i"] = ip_mac_map.max() if not ip_mac_map.empty else 1.0

    mac_ip_map = scenario_window_df.groupby("arp_src_mac")["arp_src_ip"].nunique()
    features["max_ID_m"] = mac_ip_map.max() if not mac_ip_map.empty else 1.0

    max_ri = 0.0
    ip_groups = scenario_window_df.groupby(["arp_src_ip", "arp_src_mac"]).size().reset_index(name="counts")
    for ip in ip_groups["arp_src_ip"].unique():
        counts = ip_groups[ip_groups["arp_src_ip"] == ip]["counts"]
        if len(counts) > 1:
            ri = 1 - (counts.max() / counts.sum())
            max_ri = max(max_ri, ri)
    features["max_R_i"] = max_ri

    attackers = list(attackers.values())
    for attacker in attackers:
        attacker["victim_ips"] = list(attacker["victim_ips"])

    return features, victim_ips, attackers


def build_dataframe(packet_buffer, columns, first_timestamp):
    df_window = pd.DataFrame(packet_buffer, columns=columns)
    mac_and_ip_cols = {"src_ip": "arp_src_ip", "dst_ip": "arp_dst_ip", "src_mac": "arp_src_mac"}
    df_window["timestamp"] = df_window["timestamp"].astype(float) - first_timestamp
    df_window["timedelta"] = df_window["timestamp"].diff().fillna(0)
    df_window["arp_code"] = df_window["opcode"].map({"1": 1, "2": 2}).fillna(1).astype(int)
    df_window["is_gratuitous"] = ((df_window["src_ip"] == df_window["dst_ip"]) & (df_window["src_ip"] != "")).astype(int)
    df_window["is_broadcast"] = (df_window["dst_mac"].str.lower() == "ff:ff:ff:ff:ff:ff").astype(int)
    df_window = df_window.rename(columns=mac_and_ip_cols)
    return df_window


if __name__ == "__main__":
    model_name = "arp_model_deploy.pkl"
    device, scaler_s, scaler_d, model = load_model(model_name)

    first_timestamp = None
    attack_active = False
    window_size = 3
    attack_min = 2

    real_ip_mac_map = {}
    mac_seen_ips = {}
    affected_ips = set()
    chunk_window = deque(maxlen=window_size)
    packet_buffer = []

    columns = ["timestamp", "src_mac", "src_ip", "dst_mac", "dst_ip", "opcode"]

    cmd = [
        "tshark", "-l", "-n", "-i", "virbr-labs", "-f", "arp", "-T", "fields",
        "-e", "frame.time_epoch", "-e", "eth.src", "-e", "arp.src.proto_ipv4",
        "-e", "eth.dst", "-e", "arp.dst.proto_ipv4", "-e", "arp.opcode",
        "-E", "header=n", "-E", "separator=,"
    ]

    process = subprocess.Popen(
        cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        text=True, bufsize=1, env={**os.environ, "TMPDIR": "/dev/shm"}
    )

    log("Starting live detection...")
    t_collection_start = time.time()

    try:
        for line in process.stdout:
            parts = line.strip().split(",")
            if len(parts) == 6:
                packet_buffer.append(parts)

            if len(packet_buffer) < 50:
                continue

            if first_timestamp is None:
                first_timestamp = float(packet_buffer[0][0])

            df_window = build_dataframe(packet_buffer, columns, first_timestamp)
            update_mac_history(df_window, mac_seen_ips)
            update_baseline(df_window, real_ip_mac_map, attack_active)

            timedelta_scaled = scaler_s.transform(df_window[["timedelta"]].values)
            s_final = np.hstack([timedelta_scaled, df_window[['arp_code', 'is_gratuitous', 'is_broadcast']].values])

            dynamic_dict, victim_ips, attackers = calculate_dynamic_features_global(df_window, real_ip_mac_map, mac_seen_ips, 0.1)
            d_cols = ['URR', 'RRR', 'volatility', 'max_R_i', 'max_MD_i', 'max_ID_m', 'dt_cv']
            d_raw = np.array([dynamic_dict.get(col, 0) for col in d_cols]).reshape(1, -1)
            d_final = scaler_d.transform(d_raw)

            with torch.no_grad():
                s_tensor = torch.FloatTensor(s_final).unsqueeze(0).to(device)
                d_tensor = torch.FloatTensor(d_final).to(device)
                output = model(s_tensor, d_tensor)
                prob = torch.sigmoid(output).item()

            status = "ATTACK" if prob > 0.5 else "NORMAL"
            chunk_window.append(status)
            model_attack = False
            no_attacks = chunk_window.count("ATTACK")
            if len(chunk_window) == window_size and no_attacks >= attack_min:
                model_attack = True

            valid_attackers = [a for a in attackers]
            confirmed_attack = False
            if model_attack and len(valid_attackers) > 0 and len(victim_ips) > 0:
              confirmed_attack = True

            if confirmed_attack:
                attack_active = True
                affected_ips.update(victim_ips)

                for attacker in valid_attackers:
                    log(f"IP Attacker: {attacker['attacker_ip']} | IP victims: {attacker['victim_ips']}")
                    status_dict = {
                        "status": "attack",
                        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
                        "event_type": "alert",
                        "attack_type": "ARP_SPOOFING",
                        "protocol": "ip",
                        "src_ip": attacker["attacker_ip"],
                        "src_port": -1,
                        "dest_ip": attacker["victim_ips"],
                        "dst_port": -1,
                        "alert": {
                            "signature": "ARP Spoofing attack detected",
                            "severity": 2
                        }
                    }
                    with open(suricata_json, "a") as f:
                        f.write(json.dumps(status_dict) + "\n")

                log(f"[ATTACK] Prob: {prob:.4f} | Window: {list(chunk_window)}")

            elif model_attack:
                attack_active = True
                log(f"[ATTACK - NO MAPPING FOUND] Prob: {prob:.4f} | Window: {list(chunk_window)}")

            else:
                if attack_active:
                    attack_active = False
                    affected_ips.clear()
                    clear_json()
                log(f"[Normal] Prob: {prob:.4f} | Window: {list(chunk_window)}")

            packet_buffer = []

    except KeyboardInterrupt:
        log("Stopping...")
        clear_json()
        try:
            process.terminate()
        except Exception:
            pass
