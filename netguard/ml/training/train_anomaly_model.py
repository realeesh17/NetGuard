import os
import joblib
import random
import numpy as np
from netguard.core.config import Config

try:
    from sklearn.ensemble import IsolationForest
    SKLEARN_AVAILABLE = True
except ImportError as e:
    SKLEARN_AVAILABLE = False
    SKLEARN_ERROR = e


def generate_synthetic_features(n_samples=1000):
    """
    Generate synthetic network traffic feature vectors for training the IsolationForest.
    Generates mostly normal traffic (95%) and a few anomalies (5%).
    
    Feature vector dimensions:
        1. packet_rate (float): Packets per second
        2. unique_ports (float): Count of unique destination ports
        3. avg_length (float): Average packet size in bytes
        4. tcp_ratio (float): Ratio of TCP packets [0.0 - 1.0]
        5. udp_ratio (float): Ratio of UDP packets [0.0 - 1.0]
        6. icmp_ratio (float): Ratio of ICMP packets [0.0 - 1.0]
        7. avg_entropy (float): Average entropy of payloads
    """
    X = []
    
    # 95% Normal traffic profile: low rate, small unique ports, average size, mostly TCP/UDP
    for _ in range(int(n_samples * 0.95)):
        packet_rate = random.uniform(1.0, 10.0)
        unique_ports = float(random.randint(1, 3))
        avg_length = random.uniform(64.0, 500.0)
        
        # protocol mix (must sum to 1.0)
        tcp = random.uniform(0.3, 0.7)
        udp = random.uniform(0.2, 0.5)
        icmp = 1.0 - (tcp + udp)
        
        avg_entropy = random.uniform(0.5, 2.5)
        
        X.append([packet_rate, unique_ports, avg_length, tcp, udp, icmp, avg_entropy])
        
    # 5% Anomalous traffic profile: high rates, massive port counts (scans), huge packet sizes, or protocol floods
    for _ in range(int(n_samples * 0.05)):
        anomaly_type = random.choice(["port_scan", "syn_flood", "exfiltration", "udp_flood"])
        
        if anomaly_type == "port_scan":
            packet_rate = random.uniform(20.0, 100.0)
            unique_ports = float(random.randint(20, 100))
            avg_length = random.uniform(40.0, 80.0)
            tcp = 1.0
            udp = 0.0
            icmp = 0.0
            avg_entropy = random.uniform(1.0, 3.0)
        elif anomaly_type == "syn_flood":
            packet_rate = random.uniform(50.0, 200.0)
            unique_ports = 1.0
            avg_length = 64.0
            tcp = 1.0
            udp = 0.0
            icmp = 0.0
            avg_entropy = 0.5
        elif anomaly_type == "exfiltration":
            packet_rate = random.uniform(10.0, 30.0)
            unique_ports = 1.0
            avg_length = random.uniform(1400.0, 1500.0)
            tcp = 1.0
            udp = 0.0
            icmp = 0.0
            avg_entropy = random.uniform(5.5, 7.5) # Encrypted/high entropy
        else: # udp flood
            packet_rate = random.uniform(100.0, 500.0)
            unique_ports = 1.0
            avg_length = random.uniform(500.0, 1000.0)
            tcp = 0.0
            udp = 1.0
            icmp = 0.0
            avg_entropy = random.uniform(1.5, 3.0)
            
        X.append([packet_rate, unique_ports, avg_length, tcp, udp, icmp, avg_entropy])
        
    return np.array(X)

def train_model():
    if not SKLEARN_AVAILABLE:
        print("\n" + "="*80)
        print("WARNING: MACHINE LEARNING ENGINE UNAVAILABLE")
        print("="*80)
        print("Scikit-learn / SciPy failed to load. Under local system security policies")
        print("(e.g., Application Control), native C DLLs/libraries required by Scipy/Numpy")
        print("may be blocked from executing.")
        print(f"\nError Details: {SKLEARN_ERROR}")
        print("\nFallback Action:")
        print("NetGuard will run in Rule-Based fallback mode. You do not need to train")
        print("the ML model; the packet sniffer and phishing page detectors will continue")
        print("to evaluate traffic using robust heuristic signature checks.")
        print("="*80 + "\n")
        return

    print("Generating synthetic network traffic features for training...")
    X = generate_synthetic_features(n_samples=2000)
    
    print("Training IsolationForest model...")
    # Contamination set to 5% since our dataset has 5% anomalies
    model = IsolationForest(contamination=0.05, random_state=42)
    model.fit(X)
    
    # Create models directory if it doesn't exist
    model_path = Config.ANOMALY_MODEL_PATH
    os.makedirs(os.path.dirname(model_path), exist_ok=True)
    
    joblib.dump(model, model_path)
    print(f"Anomaly detection model trained successfully and saved to {model_path}")

if __name__ == "__main__":
    train_model()

