from datetime import datetime, timezone
from sqlalchemy import Integer, String, DateTime, Float, Boolean, JSON, ForeignKey
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship

class Base(DeclarativeBase):
    pass

class Event(Base):
    __tablename__ = "events"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    timestamp: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc))
    source: Mapped[str] = mapped_column(String(50))  # "sniffer" | "phishing" | "firewall"
    severity: Mapped[str] = mapped_column(String(20))  # "info" | "warning" | "critical"
    summary: Mapped[str] = mapped_column(String(255))
    raw_data: Mapped[dict] = mapped_column(JSON, nullable=True)

    def to_dict(self):
        return {
            "id": self.id,
            "timestamp": self.timestamp.isoformat(),
            "source": self.source,
            "severity": self.severity,
            "summary": self.summary,
            "raw_data": self.raw_data
        }

class PacketLog(Base):
    __tablename__ = "packet_logs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    timestamp: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc))
    src_ip: Mapped[str] = mapped_column(String(45))
    dst_ip: Mapped[str] = mapped_column(String(45))
    protocol: Mapped[str] = mapped_column(String(10))
    length: Mapped[int] = mapped_column(Integer)
    flags: Mapped[str] = mapped_column(String(20), nullable=True)
    payload_entropy: Mapped[float] = mapped_column(Float, default=0.0)
    is_anomaly: Mapped[bool] = mapped_column(Boolean, default=False)

    def to_dict(self):
        return {
            "id": self.id,
            "timestamp": self.timestamp.isoformat(),
            "src_ip": self.src_ip,
            "dst_ip": self.dst_ip,
            "protocol": self.protocol,
            "length": self.length,
            "flags": self.flags,
            "payload_entropy": self.payload_entropy,
            "is_anomaly": self.is_anomaly
        }

class PhishingScan(Base):
    __tablename__ = "phishing_scans"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    timestamp: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc))
    url: Mapped[str] = mapped_column(String(2048))
    domain_age: Mapped[int] = mapped_column(Integer, nullable=True)  # in days
    cert_validity: Mapped[str] = mapped_column(String(100), nullable=True)
    form_action_check: Mapped[str] = mapped_column(String(100), nullable=True)
    brand_mismatch: Mapped[bool] = mapped_column(Boolean, default=False)
    ml_score: Mapped[float] = mapped_column(Float, default=0.0)
    verdict: Mapped[str] = mapped_column(String(50))  # "legitimate" | "suspicious" | "phishing"

    def to_dict(self):
        return {
            "id": self.id,
            "timestamp": self.timestamp.isoformat(),
            "url": self.url,
            "domain_age": self.domain_age,
            "cert_validity": self.cert_validity,
            "form_action_check": self.form_action_check,
            "brand_mismatch": self.brand_mismatch,
            "ml_score": self.ml_score,
            "verdict": self.verdict
        }

class FirewallRule(Base):
    __tablename__ = "firewall_rules"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    priority: Mapped[int] = mapped_column(Integer, default=0)
    action: Mapped[str] = mapped_column(String(10))  # "allow" | "deny"
    src_ip: Mapped[str] = mapped_column(String(45))  # CIDR e.g. "192.168.1.0/24" or "any"
    dst_port: Mapped[str] = mapped_column(String(20))  # Port/range, e.g. "80", "1-1024", "any"
    protocol: Mapped[str] = mapped_column(String(10))  # "TCP" | "UDP" | "ICMP" | "ANY"
    hit_count: Mapped[int] = mapped_column(Integer, default=0)

    def to_dict(self):
        return {
            "id": self.id,
            "priority": self.priority,
            "action": self.action,
            "src_ip": self.src_ip,
            "dst_port": self.dst_port,
            "protocol": self.protocol,
            "hit_count": self.hit_count
        }

class FirewallDecision(Base):
    __tablename__ = "firewall_decisions"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    timestamp: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc))
    src_ip: Mapped[str] = mapped_column(String(45))
    dst_ip: Mapped[str] = mapped_column(String(45))
    dst_port: Mapped[int] = mapped_column(Integer)
    protocol: Mapped[str] = mapped_column(String(10))
    rule_matched_id: Mapped[int] = mapped_column(Integer, nullable=True)
    action_taken: Mapped[str] = mapped_column(String(10))  # "allow" | "deny"

    def to_dict(self):
        return {
            "id": self.id,
            "timestamp": self.timestamp.isoformat(),
            "src_ip": self.src_ip,
            "dst_ip": self.dst_ip,
            "dst_port": self.dst_port,
            "protocol": self.protocol,
            "rule_matched_id": self.rule_matched_id,
            "action_taken": self.action_taken
        }
