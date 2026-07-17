from contextlib import contextmanager
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, scoped_session
from netguard.core.config import Config
from netguard.core.models import Base

# Setup SQLAlchemy engine and session factory
# Using check_same_thread=False for SQLite multithreaded/web access
engine = create_engine(Config.DB_PATH, connect_args={"check_same_thread": False})
session_factory = sessionmaker(bind=engine, expire_on_commit=False)
Session = scoped_session(session_factory)

@contextmanager
def get_session():
    """Context manager for database sessions, automatically committing or rolling back."""
    session = Session()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()

def init_db():
    """Initialize the database schema and prepopulate basic tables if empty."""
    Base.metadata.create_all(engine)
    
    # Prepopulate default firewall rules if empty
    from netguard.core.models import FirewallRule
    with get_session() as session:
        if session.query(FirewallRule).count() == 0:
            default_rules = [
                FirewallRule(priority=1, action="deny", src_ip="192.168.1.100", dst_port="any", protocol="ANY"),
                FirewallRule(priority=2, action="deny", src_ip="any", dst_port="22", protocol="TCP"),
                FirewallRule(priority=3, action="allow", src_ip="any", dst_port="80", protocol="TCP"),
                FirewallRule(priority=4, action="allow", src_ip="any", dst_port="443", protocol="TCP"),
                FirewallRule(priority=5, action="allow", src_ip="any", dst_port="any", protocol="ANY")
            ]
            session.add_all(default_rules)
            print("Database initialized with default firewall rules.")
        else:
            print("Database tables validated.")
