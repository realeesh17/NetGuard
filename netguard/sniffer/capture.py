import threading
import queue
import traceback
from netguard.core.config import Config

# Safe import of Scapy elements
try:
    from scapy.all import sniff, Packet
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

# Global state for sniffer
_sniffer_thread = None
_sniffer_running = False
_sniffer_lock = threading.Lock()
_packet_handlers = []
_handlers_lock = threading.Lock()

def register_packet_handler(callback):
    """Register a callback function to handle captured packets."""
    with _handlers_lock:
        _packet_handlers.append(callback)

def unregister_packet_handler(callback):
    """Unregister a packet callback handler."""
    with _handlers_lock:
        if callback in _packet_handlers:
            _packet_handlers.remove(callback)

def _dispatch_packet(packet):
    """Send the packet to all registered handlers."""
    with _handlers_lock:
        handlers = list(_packet_handlers)
    for handler in handlers:
        try:
            handler(packet)
        except Exception as e:
            print(f"Error in packet handler callback: {e}")

def _sniff_loop(interface, bpf_filter):
    """Internal loop executing scapy.all.sniff."""
    global _sniffer_running
    print(f"Scapy sniffing started on interface: {interface or 'default'} with filter: '{bpf_filter or ''}'")
    
    def packet_callback(packet):
        if not _sniffer_running:
            return
        _dispatch_packet(packet)

    try:
        # scapy.all.sniff will block until finished or stopped by stop_filter
        sniff(
            iface=interface,
            filter=bpf_filter,
            prn=packet_callback,
            store=False,
            stop_filter=lambda p: not _sniffer_running
        )
    except Exception as e:
        print(f"Error in live packet capture thread: {e}")
        traceback.print_exc()
        _sniffer_running = False

def start_capture(interface=None, bpf_filter=None):
    """
    Start live packet capture on a background thread.
    
    IMPORTANT: This requires root/administrator privileges on the host system,
    along with Npcap (Windows) or Libpcap (Linux/macOS) installed.
    """
    global _sniffer_thread, _sniffer_running
    
    if not SCAPY_AVAILABLE:
        print("Warning: Scapy is not installed or available. Cannot start live capture.")
        return False
        
    with _sniffer_lock:
        if _sniffer_running:
            return True
            
        # If no interface is passed, load from core config
        if interface is None:
            interface = Config.INTERFACE
            
        _sniffer_running = True
        _sniffer_thread = threading.Thread(
            target=_sniff_loop,
            args=(interface, bpf_filter),
            name="PacketSnifferThread",
            daemon=True
        )
        _sniffer_thread.start()
        return True

def stop_capture():
    """Stop the background packet sniffer thread."""
    global _sniffer_thread, _sniffer_running
    with _sniffer_lock:
        if not _sniffer_running:
            return
        _sniffer_running = False
        # Note: scapy sniff will check stop_filter on next packet arrival or timeout
        print("Packet sniffer stop signal sent.")
        
def is_sniffer_running() -> bool:
    """Return whether the sniffer thread is active."""
    return _sniffer_running
