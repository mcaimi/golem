import re
from datetime import datetime
from enum import StrEnum
from ipaddress import IPv4Address

from pydantic import BaseModel, Field, field_validator


class InstanceStatus(StrEnum):
    STARTING = "starting"
    RUNNING = "running"
    STOPPING = "stopping"
    STOPPED = "stopped"
    FAILED = "failed"


MAC_PATTERN = re.compile(r"^[0-9a-fA-F]{2}(:[0-9a-fA-F]{2}){5}$")


def _validate_interface(v: str) -> str:
    if not v.replace(".", "").replace("-", "").replace("_", "").isalnum():
        raise ValueError("Interface name contains invalid characters")
    return v


class SpooferStartRequest(BaseModel):
    interface: str = Field(
        ..., min_length=1, max_length=15, examples=["eth0", "en0"]
    )
    victim1_ip: IPv4Address = Field(..., examples=["192.168.1.10"])
    victim2_ip: IPv4Address = Field(..., examples=["192.168.1.20"])
    timing_ms: int = Field(
        default=2000,
        ge=2000,
        description="Flood timing in milliseconds (minimum 2000)",
    )

    @field_validator("interface")
    @classmethod
    def validate_interface(cls, v: str) -> str:
        return _validate_interface(v)

    @field_validator("victim2_ip")
    @classmethod
    def victims_must_differ(cls, v: IPv4Address, info) -> IPv4Address:
        if "victim1_ip" in info.data and info.data["victim1_ip"] == v:
            raise ValueError("victim1_ip and victim2_ip must be different")
        return v


class GratuitousArpRequest(BaseModel):
    interface: str = Field(
        ..., min_length=1, max_length=15, examples=["eth0", "en0"]
    )
    router_ip: IPv4Address = Field(..., examples=["192.168.1.1"])
    new_ip: IPv4Address = Field(..., examples=["192.168.1.99"])
    new_mac: str = Field(..., examples=["aa:bb:cc:dd:ee:ff"])

    @field_validator("interface")
    @classmethod
    def validate_interface(cls, v: str) -> str:
        return _validate_interface(v)

    @field_validator("new_mac")
    @classmethod
    def validate_mac(cls, v: str) -> str:
        if not MAC_PATTERN.match(v):
            raise ValueError(
                "Invalid MAC address format, expected xx:xx:xx:xx:xx:xx"
            )
        return v.lower()


class SpooferInstance(BaseModel):
    id: str = Field(..., description="Unique instance UUID")
    pid: int = Field(..., description="OS process ID")
    mode: int = Field(..., description="Operation mode: 0=ARP Poison, 1=Gratuitous ARP")
    interface: str
    status: InstanceStatus
    started_at: datetime
    stopped_at: datetime | None = None
    timing_ms: int
    victim1_ip: str | None = None
    victim2_ip: str | None = None
    victim1_mac: str | None = None
    victim2_mac: str | None = None
    attacker_ip: str | None = None
    attacker_mac: str | None = None
    router_ip: str | None = None
    new_ip: str | None = None
    new_mac: str | None = None
    router_mac: str | None = None


class SpooferStartResponse(BaseModel):
    id: str
    pid: int
    status: InstanceStatus
    message: str


class SpooferStopResponse(BaseModel):
    id: str
    pid: int
    status: InstanceStatus
    message: str


class SpooferListResponse(BaseModel):
    instances: list[SpooferInstance]
    count: int


class ErrorResponse(BaseModel):
    detail: str


class HealthResponse(BaseModel):
    status: str
    running_instances: int
    is_root: bool
    binary_exists: bool
