import subprocess
import pandas as pd
import numpy as np
import torch
import torch.nn as nn
import math
import pickle
import sys

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
        encoder_layer = nn.TransformerEncoderLayer(
            d_model=embed_dim, nhead=4, dim_feedforward=128, 
            dropout=0.3, batch_first=True, activation='gelu'
        )
        self.transformer = nn.TransformerEncoder(encoder_layer, num_layers=1)
        self.dynamic_projection = nn.Sequential(
            nn.Linear(dynamic_dim, embed_dim),
            nn.GELU()
        )
        self.classifier = nn.Sequential(
            nn.Linear(embed_dim * 2, 32),
            nn.GELU(),
            nn.Dropout(0.3),
            nn.Linear(32, 1)
        )

    def forward(self, x_static, x_dynamic):
        seq_features = self.embedding(x_static)
        seq_features = self.pos_encoder(seq_features)
        seq_out = self.transformer(seq_features)
        seq_representation = seq_out.mean(dim=1) 
        dyn_representation = self.dynamic_projection(x_dynamic)
        combined = torch.cat([seq_representation, dyn_representation], dim=1)
        return self.classifier(combined)


try:
    with open('arp_model_deploy.pkl', 'rb') as f:
        deploy_data = pickle.load(f)

    model = deploy_data['model']
    scaler_s = deploy_data['scaler_s']
    scaler_d = deploy_data['scaler_d']
    
    device = 'cuda' if torch.cuda.is_available() else 'cpu'
    model.to(device)
    model.eval()
    print(f"Model loaded on {device}.")
except Exception as e:
    print(f"Error loading model: {e}")
    sys.exit(1)


def calculate_static_features(scenario_df, ip_gateway="192.168.2.1"):
    df = pd.DataFrame()
    df['timedelta'] = scenario_df['timestamp'].diff().fillna(0)
    df['arp_code'] = scenario_df['arp_code']
    df['is_gratuitous'] = scenario_df['is_gratuitous']
    df['is_broadcast'] = scenario_df['is_broadcast']

    return df

def calculate_dynamic_features_global(scenario_window_df, delta=0.1):
    features = {}
    n_requests = (scenario_window_df['arp_code'] == 1).sum()
    n_replies = (scenario_window_df['arp_code'] == 2).sum()
    features['RRR'] = min(n_replies / n_requests, 10.0) if n_requests > 0 else float(n_replies)

    requested_ips = set(scenario_window_df[scenario_window_df['arp_code'] == 1]['arp_dst_ip'])
    orphan_replies = 0
    for _, row in scenario_window_df[scenario_window_df['arp_code'] == 2].iterrows():
        if row['arp_src_ip'] not in requested_ips:
            orphan_replies += 1
    features['URR'] = orphan_replies / (n_replies + 1e-9)

    timedeltas = scenario_window_df['timedelta']
    features['volatility'] = (timedeltas < delta).sum() / len(scenario_window_df)
    features['dt_cv'] = timedeltas.std() / (timedeltas.mean() + 1e-9)

    ip_mac_map = scenario_window_df.groupby('arp_src_ip')['arp_src_mac'].nunique()
    mac_ip_map = scenario_window_df.groupby('arp_src_mac')['arp_src_ip'].nunique()
    features['max_MD_i'] = ip_mac_map.max() if not ip_mac_map.empty else 1.0
    features['max_ID_m'] = mac_ip_map.max() if not mac_ip_map.empty else 1.0

    max_ri = 0.0
    ip_groups = scenario_window_df.groupby(['arp_src_ip', 'arp_src_mac']).size().reset_index(name='counts')
    for ip in ip_groups['arp_src_ip'].unique():
        counts = ip_groups[ip_groups['arp_src_ip'] == ip]['counts']
        if len(counts) > 1:
            ri = 1 - (counts.max() / counts.sum())
            max_ri = max(max_ri, ri)
    features['max_R_i'] = max_ri
    return features

cmd = [
    "tshark", "-i", "virbr-labs", "-f", "arp", "-T", "fields",
    "-e", "frame.time_epoch", "-e", "eth.src", "-e", "arp.src.proto_ipv4",
    "-e", "eth.dst", "-e", "arp.dst.proto_ipv4", "-e", "arp.opcode",
    "-E", "header=n", "-E", "separator=,"
]

process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
columns = ["timestamp", "src_mac", "src_ip", "dst_mac", "dst_ip", "opcode"]
packet_buffer = []
first_timestamp = None

print("Starting live detection...")

try:
    for line in process.stdout:
        parts = line.strip().split(",")
        if len(parts) == 6:
            packet_buffer.append(parts)

        if len(packet_buffer) == 50:
            if first_timestamp is None:
                first_timestamp = float(packet_buffer[0][0])

            df_window = pd.DataFrame(packet_buffer, columns=columns)
            df_window["timestamp"] = df_window["timestamp"].astype(float) - first_timestamp
            df_window['timedelta'] = df_window['timestamp'].diff().fillna(0)
            df_window['arp_code'] = df_window['opcode'].map({"1": 1, "2": 2}).fillna(1).astype(int)
            df_window['is_gratuitous'] = ((df_window['src_ip'] == df_window['dst_ip']) & (df_window['src_ip'] != "")).astype(int)
            df_window['is_broadcast'] = (df_window['dst_mac'].str.lower() == "ff:ff:ff:ff:ff:ff").astype(int)
            df_window = df_window.rename(columns={'src_ip': 'arp_src_ip', 'dst_ip': 'arp_dst_ip', 'src_mac': 'arp_src_mac'})

            timedelta_scaled = scaler_s.transform(df_window[['timedelta']].values)
            
            s_final = np.hstack([
                timedelta_scaled, 
                df_window[['arp_code', 'is_gratuitous', 'is_broadcast']].values
            ])

            dynamic_dict = calculate_dynamic_features_global(df_window, 0.1)
            d_cols = ['URR', 'RRR', 'volatility', 'max_R_i', 'max_MD_i', 'max_ID_m', 'dt_cv']
            d_raw = np.array([dynamic_dict.get(col, 0) for col in d_cols]).reshape(1, -1)
            d_final = scaler_d.transform(d_raw)

            with torch.no_grad():
                s_tensor = torch.FloatTensor(s_final).unsqueeze(0).to(device)
                d_tensor = torch.FloatTensor(d_final).to(device)

                output = model(s_tensor, d_tensor)
                prob = torch.sigmoid(output).item()

            status = "ATTACK" if prob > 0.5 else "Normal"
            print(f"{status} | Prob: {prob:.4f} | Ri: {dynamic_dict['max_R_i']:.2f} | MD: {dynamic_dict['max_MD_i']:.0f}")

            packet_buffer = []

except KeyboardInterrupt:
    print("\nStopping...")
    process.terminate()