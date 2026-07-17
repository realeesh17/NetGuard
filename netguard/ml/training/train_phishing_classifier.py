"""
Phishing Page Classifier Training Script

Expected Dataset Structure:
Place CSV datasets in `netguard/data/datasets/`.
The script expects a consolidated CSV file named `phishing_dataset.csv` with columns:
  - `url` (string): The URL of the website to inspect.
  - `label` (int): 1 if phishing, 0 if legitimate.

Alternatively, place:
  - `phishing_urls.csv` with a 'url' column (all labeled as 1)
  - `legit_urls.csv` with a 'url' column (all labeled as 0)

The training script will:
  1. Load the URLs.
  2. Parse and fetch live or cached details (or extract features).
  3. Train a LogisticRegression model (RandomForest option commented out).
  4. Save the trained model to `netguard/ml/models/phishing_model.pkl`.
"""

import os
import sys
import joblib
import pandas as pd

try:
    from sklearn.model_selection import train_test_split
    from sklearn.linear_model import LogisticRegression
    from sklearn.ensemble import RandomForestClassifier
    from sklearn.metrics import classification_report, accuracy_score, precision_recall_fscore_support
    SKLEARN_AVAILABLE = True
except ImportError as e:
    SKLEARN_AVAILABLE = False
    SKLEARN_ERROR = e


from netguard.core.config import Config
from netguard.phishing.analyze import extract_phishing_features
from netguard.phishing.fetch import fetch_url
from netguard.phishing.cert import get_cert_details
from netguard.phishing.domain import get_domain_info
from netguard.phishing.content import analyze_content

DATASETS_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), "data", "datasets")

def check_dataset() -> tuple[list[str], list[int]]:
    """Check for datasets and load them, or fail with instructions."""
    consolidated_path = os.path.join(DATASETS_DIR, "phishing_dataset.csv")
    phish_path = os.path.join(DATASETS_DIR, "phishing_urls.csv")
    legit_path = os.path.join(DATASETS_DIR, "legit_urls.csv")
    
    urls = []
    labels = []
    
    if os.path.exists(consolidated_path):
        print(f"Loading dataset from: {consolidated_path}")
        df = pd.read_csv(consolidated_path)
        if "url" not in df.columns or "label" not in df.columns:
            print("Error: Consolidated dataset must contain 'url' and 'label' columns.")
            sys.exit(1)
        urls = df["url"].tolist()
        labels = df["label"].tolist()
    elif os.path.exists(phish_path) and os.path.exists(legit_path):
        print(f"Loading datasets from: {phish_path} and {legit_path}")
        df_phish = pd.read_csv(phish_path)
        df_legit = pd.read_csv(legit_path)
        
        if "url" not in df_phish.columns or "url" not in df_legit.columns:
            print("Error: Datasets must contain a 'url' column.")
            sys.exit(1)
            
        urls.extend(df_phish["url"].tolist())
        labels.extend([1] * len(df_phish))
        
        urls.extend(df_legit["url"].tolist())
        labels.extend([0] * len(df_legit))
    else:
        print("\n" + "="*80)
        print("ERROR: TRAINING DATASET NOT FOUND")
        print("="*80)
        print(f"Please place your training data inside: {DATASETS_DIR}")
        print("\nYou can either provide:")
        print("1. A consolidated file named 'phishing_dataset.csv' with columns: 'url' and 'label'")
        print("   OR")
        print("2. Two separate CSV files: 'phishing_urls.csv' and 'legit_urls.csv', each containing a 'url' column.")
        print("\nNote: PhishTank feeds (phishing) and Tranco lists (legitimate) are recommended.")
        print("="*80 + "\n")
        raise FileNotFoundError(f"Missing training datasets in {DATASETS_DIR}")
        
    return urls, labels

def extract_features_for_dataset(urls: list[str]) -> list[list[float]]:
    """Fetch URL details and extract the 10-dimensional feature vector for each URL."""
    features_list = []
    print(f"Extracting features for {len(urls)} URLs. This performs simulated/live scans...")
    
    for i, url in enumerate(urls):
        if not url.startswith(("http://", "https://")):
            url = "http://" + url
            
        print(f"[{i+1}/{len(urls)}] Processing {url}...")
        
        # In a real environment, we'd run fetch, whois, cert, content.
        # To avoid blocking the training script with real internet requests on thousands of sites,
        # we try fetching. If it fails, we catch it and use default offline fallback parameters.
        fetch_res = fetch_url(url, timeout=2.0)
        final_url = fetch_res["redirect_chain"][-1] if fetch_res["redirect_chain"] else url
        cert_res = get_cert_details(final_url, timeout=2.0)
        whois_res = get_domain_info(final_url)
        content_res = analyze_content(fetch_res["html"], final_url)
        
        feats = extract_phishing_features(url, fetch_res, cert_res, whois_res, content_res)
        features_list.append(feats)
        
    return features_list

def train_classifier():
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
        print("the ML model; the phishing page detector will continue to evaluate URLs")
        print("using robust, explainable rule checks (domain age, certificate validation,")
        print("form action checks, brand mismatch, etc.).")
        print("="*80 + "\n")
        return

    # 1. Load URLs and labels
    try:
        urls, labels = check_dataset()
    except FileNotFoundError:
        sys.exit(1)
        
    # 2. Extract features
    X = extract_features_for_dataset(urls)
    y = labels
    
    # 3. Train-Test Split
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)
    
    # 4. Train Model
    print("Training LogisticRegression Classifier...")
    model = LogisticRegression(max_iter=1000)
    
    # Commented-out RandomForest alternative:
    # print("Training RandomForest Classifier...")
    # model = RandomForestClassifier(n_estimators=100, random_state=42)
    
    model.fit(X_train, y_train)
    
    # 5. Evaluate
    y_pred = model.predict(X_test)
    print("\n" + "="*40)
    print("EVALUATION METRICS")
    print("="*40)
    print(f"Accuracy: {accuracy_score(y_test, y_pred):.4f}")
    print("\nClassification Report:")
    print(classification_report(y_test, y_pred, target_names=["Legitimate", "Phishing"]))
    print("="*40)
    
    # 6. Save model
    model_path = Config.PHISHING_MODEL_PATH
    os.makedirs(os.path.dirname(model_path), exist_ok=True)
    joblib.dump(model, model_path)
    print(f"\nPhishing model successfully saved to {model_path}")

if __name__ == "__main__":
    train_classifier()

