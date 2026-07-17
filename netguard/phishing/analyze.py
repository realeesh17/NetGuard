import os
import joblib
from urllib.parse import urlparse
from netguard.core.config import Config
from netguard.core.db import get_session
from netguard.core.models import PhishingScan
from netguard.core.events import log_event

from netguard.phishing.fetch import fetch_url
from netguard.phishing.cert import get_cert_details
from netguard.phishing.domain import get_domain_info
from netguard.phishing.content import analyze_content

# Cache for loaded phishing classifier model
_phishing_model = None
_model_loaded = False

def load_phishing_model():
    """Load the pre-trained phishing classifier from disk."""
    global _phishing_model, _model_loaded
    model_path = Config.PHISHING_MODEL_PATH
    if os.path.exists(model_path):
        try:
            _phishing_model = joblib.load(model_path)
            _model_loaded = True
            print(f"Phishing ML Classifier successfully loaded from: {model_path}")
            return True
        except Exception as e:
            print(f"Warning: Failed to load phishing model from {model_path}: {e}")
            _phishing_model = None
            _model_loaded = False
    else:
        _phishing_model = None
        _model_loaded = False
    return False

def extract_phishing_features(url: str, fetch_res: dict, cert_res: dict, whois_res: dict, content_res: dict) -> list[float]:
    """
    Extract a 10-dimensional feature vector for the phishing machine learning classifier.
    
    Features:
        1. domain_age_days (float): Raw days or 3650.0 if missing/unregistered
        2. has_valid_cert (float): 1.0 if TLS is valid, 0.0 otherwise
        3. is_self_signed (float): 1.0 if self-signed TLS cert, 0.0 otherwise
        4. redirect_chain_len (float): Length of the redirect chain
        5. has_password_field (float): 1.0 if password input exists, 0.0 otherwise
        6. off_domain_forms_count (float): Count of forms submitting off-domain
        7. brand_mismatch (float): 1.0 if brand name mismatched in text vs domain, 0.0 otherwise
        8. obfuscated_js (float): 1.0 if obfuscated JS detected, 0.0 otherwise
        9. off_domain_favicon (float): 1.0 if favicon points off-domain, 0.0 otherwise
        10. insecure_password (float): 1.0 if password field exists on HTTP, 0.0 otherwise
    """
    age = whois_res.get("domain_age_days")
    domain_age = float(age) if age is not None else 3650.0
    
    has_valid_cert = 1.0 if cert_res.get("valid") else 0.0
    is_self_signed = 1.0 if cert_res.get("self_signed") else 0.0
    redirect_len = float(len(fetch_res.get("redirect_chain", [])))
    
    has_pwd = 1.0 if content_res.get("has_password_field") else 0.0
    off_domain_forms = float(content_res.get("off_domain_forms_count", 0))
    brand_mismatch = 1.0 if content_res.get("brand_mismatch") else 0.0
    obfuscated_js = 1.0 if content_res.get("obfuscated_js_detected") else 0.0
    off_domain_fav = 1.0 if content_res.get("off_domain_favicon") else 0.0
    
    insecure_pwd = 0.0
    if has_pwd == 1.0 and not cert_res.get("valid"):
        insecure_pwd = 1.0
        
    return [
        domain_age,
        has_valid_cert,
        is_self_signed,
        redirect_len,
        has_pwd,
        off_domain_forms,
        brand_mismatch,
        obfuscated_js,
        off_domain_fav,
        insecure_pwd
    ]

def analyze_url(url: str) -> dict:
    """
    Orchestrate the URL phishing analysis pipeline:
    fetch -> cert -> whois -> content parsing -> heuristics & ML scoring -> DB logging -> event logging.
    
    Returns:
        dict: {
            "score": float (0.0 to 100.0),
            "verdict": str ('legitimate' | 'suspicious' | 'phishing'),
            "reasons": list[str]
        }
    """
    global _phishing_model, _model_loaded
    
    # 1. Fetch URL content
    fetch_res = fetch_url(url)
    final_url = fetch_res["redirect_chain"][-1] if fetch_res["redirect_chain"] else url
    
    # 2. Get TLS cert details
    cert_res = get_cert_details(final_url)
    
    # 3. Get WHOIS information
    whois_res = get_domain_info(final_url)
    
    # 4. Analyze BeautifulSoup content heuristics
    content_res = analyze_content(fetch_res["html"], final_url)
    
    # Compute Rule-based features and reasons
    reasons = []
    heuristic_score = 0
    
    # Check domain age
    age = whois_res.get("domain_age_days")
    if age is not None:
        if age < 30:
            heuristic_score += 35
            reasons.append(f"Domain is extremely young ({age} days old).")
        elif age < 90:
            heuristic_score += 15
            reasons.append(f"Domain is relatively new ({age} days old).")
    else:
        # If WHOIS failed, we assign small suspicion if it's not a local IP
        parsed_url = urlparse(final_url)
        host = parsed_url.hostname or ""
        if host and not (host.startswith("127.") or host == "localhost"):
            heuristic_score += 10
            reasons.append("WHOIS registry record not found or inaccessible.")
            
    # Check certificate status
    if url.lower().startswith("https://"):
        if not cert_res["has_cert"]:
            heuristic_score += 25
            reasons.append("Missing SSL/TLS certificate on HTTPS scheme.")
        elif not cert_res["valid"]:
            heuristic_score += 20
            reasons.append("Invalid or untrusted SSL/TLS certificate.")
        elif cert_res["self_signed"]:
            heuristic_score += 15
            reasons.append("Self-signed SSL/TLS certificate detected.")
    else:
        # HTTP website
        if content_res["has_password_field"]:
            heuristic_score += 35
            reasons.append("Sensitive password input field found over insecure HTTP connection.")
            
    # Check redirects
    redirects_count = len(fetch_res["redirect_chain"]) - 1
    if redirects_count > 3:
        heuristic_score += 15
        reasons.append(f"High number of HTTP redirects ({redirects_count}) in redirect chain.")
        
    # Check content elements
    off_domain_forms = content_res["off_domain_forms_count"]
    if off_domain_forms > 0:
        pts = min(40, off_domain_forms * 20)
        heuristic_score += pts
        reasons.append(f"Submits forms to off-domain destinations ({off_domain_forms} occurrences).")
        
    if content_res["brand_mismatch"]:
        heuristic_score += 40
        reasons.append("Brand name mismatch detected in content vs. actual domain.")
        
    if content_res["obfuscated_js_detected"]:
        heuristic_score += 20
        reasons.append("Obfuscated or high-entropy inline Javascript block detected.")
        
    if content_res["off_domain_favicon"]:
        heuristic_score += 10
        reasons.append("Favicon image resources loaded from external off-domain server.")
        
    # Cap heuristic score at 100
    heuristic_score = min(100.0, float(heuristic_score))
    
    # 5. Extract feature vector and run ML classifier if loaded
    features = extract_phishing_features(url, fetch_res, cert_res, whois_res, content_res)
    
    if not _model_loaded and _phishing_model is None:
        load_phishing_model()
        
    if _phishing_model is not None:
        try:
            # Predict probability of phishing class
            # expect binary class [legitimate, phishing]
            probs = _phishing_model.predict_proba([features])[0]
            ml_score = float(probs[1]) * 100.0
            
            # Combine scores: 60% ML, 40% Heuristics for hybrid robust system
            final_score = round((0.6 * ml_score) + (0.4 * heuristic_score), 1)
        except Exception as e:
            print(f"ML Phishing classification error: {e}")
            final_score = float(heuristic_score)
    else:
        final_score = float(heuristic_score)
        
    # Determine verdict
    if final_score >= 70.0:
        verdict = "phishing"
    elif final_score >= 35.0:
        verdict = "suspicious"
    else:
        verdict = "legitimate"
        if not reasons:
            reasons.append("No suspicious indicators identified.")
            
    # 6. Save the scan report to the database
    with get_session() as session:
        scan = PhishingScan(
            url=url,
            domain_age=age,
            cert_validity="Valid" if cert_res.get("valid") else ("Self-Signed" if cert_res.get("self_signed") else "Invalid/None"),
            form_action_check=f"{off_domain_forms} off-domain forms",
            brand_mismatch=content_res["brand_mismatch"],
            ml_score=final_score,
            verdict=verdict
        )
        session.add(scan)
        
    # 7. Log event through core event bus
    severity = "critical" if verdict == "phishing" else ("warning" if verdict == "suspicious" else "info")
    summary = f"Phishing Scan: {verdict.upper()} verdict for {url} (Score: {final_score}%)"
    
    log_event(
        source="phishing",
        severity=severity,
        summary=summary,
        raw_data={
            "url": url,
            "final_url": final_url,
            "score": final_score,
            "verdict": verdict,
            "reasons": reasons,
            "cert": cert_res,
            "whois": whois_res,
            "content": content_res
        }
    )
    
    return {
        "score": final_score,
        "verdict": verdict,
        "reasons": reasons
    }
