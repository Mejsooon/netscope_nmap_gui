from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

Protocol = Literal["tcp", "udp", "sctp", "ip"]
PortState = Literal["open", "closed", "filtered", "unfiltered", "open|filtered", "closed|filtered"]


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
