from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, IPvAnyAddress, model_validator

Protocol = Literal["tcp", "udp", "sctp", "ip"]
PortState = Literal["open", "closed", "filtered", "unfiltered", "open|filtered", "closed|filtered"]
HostState = Literal["up", "down", "unknown", "skipped"]

MAC_PATTERN = r"^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$"


class NetScopeModel(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")


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
