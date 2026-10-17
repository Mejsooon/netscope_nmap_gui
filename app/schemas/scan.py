from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, IPvAnyAddress

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
