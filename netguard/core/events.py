import threading
from datetime import datetime, timezone
from netguard.core.db import get_session
from netguard.core.models import Event

# Global thread-safe list of event listeners
_listeners = []
_listeners_lock = threading.Lock()

def register_event_listener(callback):
    """Register a callback to be invoked whenever a new event is logged."""
    with _listeners_lock:
        _listeners.append(callback)

def unregister_event_listener(callback):
    """Unregister a previously registered event callback."""
    with _listeners_lock:
        if callback in _listeners:
            _listeners.remove(callback)

def log_event(source: str, severity: str, summary: str, raw_data: dict = None) -> Event:
    """
    Log an event to the SQLite database and notify all registered callbacks.
    
    Args:
        source: 'sniffer' | 'phishing' | 'firewall'
        severity: 'info' | 'warning' | 'critical'
        summary: Human-readable description
        raw_data: Optional dictionary containing extra logs/features
    """
    event = Event(
        timestamp=datetime.now(timezone.utc),
        source=source,
        severity=severity,
        summary=summary,
        raw_data=raw_data
    )
    
    with get_session() as session:
        session.add(event)
        session.flush()  # get ID
        event_dict = event.to_dict()
    
    # Notify listeners in a thread-safe manner
    with _listeners_lock:
        callbacks = list(_listeners)
        
    for callback in callbacks:
        try:
            callback(event_dict)
        except Exception as e:
            print(f"Error in event listener callback: {e}")
            
    return event
