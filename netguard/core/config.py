import os
from pathlib import Path

# Base directory of the project
BASE_DIR = Path(__file__).resolve().parent.parent

class Config:
    # Database configuration
    DB_PATH = os.getenv("NETGUARD_DB_PATH", f"sqlite:///{BASE_DIR}/netguard.db")
    
    # Sniffer configuration
    # Can be set to a specific interface like "Wi-Fi", "Ethernet", etc.
    # If None, Scapy will use the default interface.
    INTERFACE = os.getenv("NETGUARD_INTERFACE", None)
    
    # Machine learning model paths
    ANOMALY_MODEL_PATH = os.getenv(
        "NETGUARD_ANOMALY_MODEL_PATH", 
        str(BASE_DIR / "ml" / "models" / "anomaly_model.pkl")
    )
    PHISHING_MODEL_PATH = os.getenv(
        "NETGUARD_PHISHING_MODEL_PATH", 
        str(BASE_DIR / "ml" / "models" / "phishing_model.pkl")
    )
    
    # Detection thresholds
    ANOMALY_THRESHOLD = float(os.getenv("NETGUARD_ANOMALY_THRESHOLD", -0.5))
    PORT_SCAN_THRESHOLD = int(os.getenv("NETGUARD_PORT_SCAN_THRESHOLD", 15))  # unique ports in 10s
    SYN_FLOOD_THRESHOLD = int(os.getenv("NETGUARD_SYN_FLOOD_THRESHOLD", 30))  # SYN count threshold
    SYN_ACK_RATIO_THRESHOLD = float(os.getenv("NETGUARD_SYN_ACK_RATIO_THRESHOLD", 0.1))
    
    # System mode
    FIREWALL_MODE = os.getenv("NETGUARD_FIREWALL_MODE", "synthetic")  # "synthetic" or "live"
