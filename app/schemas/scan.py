from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, IPvAnyAddress, model_validator

Protocol = Literal["tcp", "udp", "sctp", "ip"]
PortState = Literal["open", "closed", "filtered", "unfiltered", "open|filtered", "closed|filtered"]
HostState = Literal["up", "down", "unknown", "skipped"]
ScanType = Literal["connect", "syn", "udp", "ping"]

MAC_PATTERN = r"^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$"


class NetScopeModel(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")


class ScanRequest(NetScopeModel):
    target: str = Field(min_length=1, max_length=253)
    scan_type: ScanType = "connect"
    ports: str | None = Field(default=None, min_length=1, max_length=200)
    service_detection: bool = False
    os_detection: bool = False
    timing: int = Field(default=3, ge=0, le=5)


class PortResult(NetScopeModel):
    port: int = Field(ge=1, le=65535)
    protocol: Protocol
    state: PortState
    reason: str | None = None
    service_name: str | None = None
    product: str | None = None
    version: str | None = None
    extra_info: str | None = None


class ExtraPortsResult(NetScopeModel):
    state: PortState
    count: int = Field(ge=0)


class HostResult(NetScopeModel):
    state: HostState
    ip: IPvAnyAddress | None = None
    mac: str | None = Field(default=None, pattern=MAC_PATTERN)
    mac_vendor: str | None = None
    hostnames: list[str] = Field(default_factory=list)
    ports: list[PortResult] = Field(default_factory=list)
    extra_ports: list[ExtraPortsResult] = Field(default_factory=list)


class ScanResult(NetScopeModel):
    nmap_version: str
    args: str
    started_at: datetime
    finished_at: datetime | None = None
    elapsed_seconds: float | None = Field(default=None, ge=0)
    hosts_up: int = Field(ge=0)
    hosts_down: int = Field(ge=0)
    hosts_total: int = Field(ge=0)
    hosts: list[HostResult] = Field(default_factory=list)

    @model_validator(mode="after")
    def check_host_counts(self) -> "ScanResult":
        if self.hosts_up + self.hosts_down != self.hosts_total:
            raise ValueError("hosts_up + hosts_down must equal hosts_total")
        return self
