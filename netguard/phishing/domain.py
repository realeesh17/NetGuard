import whois
import time
import threading
from urllib.parse import urlparse
from datetime import datetime, timezone

# Simple in-memory cache to prevent duplicate queries and rate limits
_whois_cache = {}
_cache_lock = threading.Lock()
# Throttling delay to avoid spamming WHOIS servers
_last_lookup_time = 0.0
_lookup_lock = threading.Lock()

def get_domain_info(url: str) -> dict:
    """
    Perform a WHOIS query to fetch domain age (in days), registrar, and expiry date.
    Implements caching and rate-limiting to prevent IP blocking from registrars.
    
    Returns:
        dict: {
            "domain_age_days": int | None,
            "registrar": str | None,
            "expiry_date": str | None
        }
    """
    global _last_lookup_time
    
    result = {
        "domain_age_days": None,
        "registrar": None,
        "expiry_date": None
    }
    
    parsed = urlparse(url)
    domain = parsed.hostname or parsed.path
    if not domain:
        return result
        
    if domain.startswith("www."):
        domain = domain[4:]
        
    # Strip port if present
    if ":" in domain:
        domain = domain.split(":")[0]
        
    # Check cache first
    with _cache_lock:
        if domain in _whois_cache:
            return _whois_cache[domain]
            
    # Apply rate-limiting (max 1 request per 2 seconds globally)
    with _lookup_lock:
        now = time.time()
        elapsed = now - _last_lookup_time
        if elapsed < 2.0:
            time.sleep(2.0 - elapsed)
        _last_lookup_time = time.time()
        
        try:
            w = whois.whois(domain)
            
            # Extract creation date
            creation_date = w.get("creation_date")
            if isinstance(creation_date, list):
                creation_date = creation_date[0]
                
            # Extract expiration date
            expiration_date = w.get("expiration_date")
            if isinstance(expiration_date, list):
                expiration_date = expiration_date[0]
                
            registrar = w.get("registrar")
            if isinstance(registrar, list):
                registrar = registrar[0]
                
            # Calculate domain age in days
            age_days = None
            if isinstance(creation_date, datetime):
                # Make naive datetime timezone-aware or vice versa
                now_naive = datetime.now()
                age_days = (now_naive - creation_date).days
                
            expiry_str = None
            if isinstance(expiration_date, datetime):
                expiry_str = expiration_date.isoformat()
            elif expiration_date:
                expiry_str = str(expiration_date)
                
            result["domain_age_days"] = age_days
            result["registrar"] = str(registrar) if registrar else None
            result["expiry_date"] = expiry_str
            
        except Exception as e:
            # Domain lookup may fail if WHOIS server is down or domain is unregistered/local
            print(f"WHOIS lookup failed for {domain}: {e}")
            
    # Cache result
    with _cache_lock:
        _whois_cache[domain] = result
        
    return result
