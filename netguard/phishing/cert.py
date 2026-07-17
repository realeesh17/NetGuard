import socket
import ssl
from urllib.parse import urlparse
from datetime import datetime, timezone
import OpenSSL.crypto as crypto

def get_cert_details(url: str, timeout: float = 3.0) -> dict:
    """
    Establish a TLS connection to check SSL certificate validity, self-signed status, 
    issuer, and expiration days.
    
    Returns:
        dict: {
            "has_cert": bool,
            "issuer": str | None,
            "valid": bool,
            "self_signed": bool,
            "days_to_expiry": int
        }
    """
    result = {
        "has_cert": False,
        "issuer": None,
        "valid": False,
        "self_signed": False,
        "days_to_expiry": 0
    }
    
    parsed = urlparse(url)
    hostname = parsed.hostname or parsed.path
    if not hostname or ":" in hostname:
        # Strip port if present in hostname
        hostname = hostname.split(":")[0]
        
    # Check if we should even connect (needs to be HTTPS or implied)
    if parsed.scheme and parsed.scheme.lower() != "https":
        return result
        
    # Connect and grab cert
    # 1. Try to connect checking verification
    ctx_verify = ssl.create_default_context()
    ctx_verify.timeout = timeout
    
    ctx_no_verify = ssl.create_default_context()
    ctx_no_verify.check_hostname = False
    ctx_no_verify.verify_mode = ssl.CERT_NONE
    ctx_no_verify.timeout = timeout
    
    ssock = None
    cert_valid = False
    
    try:
        # First test if verified connection succeeds
        sock = socket.create_connection((hostname, 443), timeout=timeout)
        try:
            ssock = ctx_verify.wrap_socket(sock, server_hostname=hostname)
            cert_valid = True
        except ssl.SSLError:
            # Reconnect without verification to extract details of the invalid cert
            sock.close()
            sock = socket.create_connection((hostname, 443), timeout=timeout)
            ssock = ctx_no_verify.wrap_socket(sock, server_hostname=hostname)
            cert_valid = False
            
        der_cert = ssock.getpeercert(binary_form=True)
        ssock.close()
        sock.close()
        
        # Parse certificate using PyOpenSSL (cryptography)
        x509 = crypto.load_certificate(crypto.FILETYPE_ASN1, der_cert)
        
        # Extract issuer common name
        issuer = None
        for name, value in x509.get_issuer().get_components():
            if name.decode("utf-8") == "CN":
                issuer = value.decode("utf-8")
                break
        if not issuer:
            issuer = str(x509.get_issuer())
            
        # Check self-signed status
        # A cert is self-signed if the issuer matches the subject
        subject_name = x509.get_subject().der()
        issuer_name = x509.get_issuer().der()
        self_signed = (subject_name == issuer_name)
        
        # Expiry calculation
        # pyOpenSSL returns bytes: b'20241231235959Z'
        not_after_str = x509.get_notAfter().decode("utf-8")
        expiry_date = datetime.strptime(not_after_str, "%Y%m%d%H%M%SZ").replace(tzinfo=timezone.utc)
        days_to_expiry = (expiry_date - datetime.now(timezone.utc)).days
        
        result["has_cert"] = True
        result["issuer"] = issuer
        result["valid"] = cert_valid and (days_to_expiry > 0)
        result["self_signed"] = self_signed
        result["days_to_expiry"] = max(0, days_to_expiry)
        
    except Exception as e:
        # Graceful fallback on connection/lookup failure
        print(f"SSL certificate inspection failed for {hostname}: {e}")
        if ssock:
            try:
                ssock.close()
            except Exception:
                pass
                
    return result
