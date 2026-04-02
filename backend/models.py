from pydantic import BaseModel, Field
from typing import Optional
from enum import Enum
from datetime import datetime


class ScanProfile(str, Enum):
    quick = "quick"
    common = "common"
    full = "full"
    custom = "custom"


class ScanRequest(BaseModel):
    target: str = Field(..., min_length=1, max_length=255)
    profile: ScanProfile = ScanProfile.common
    start_port: Optional[int] = Field(None, ge=0, le=65535)
    end_port: Optional[int] = Field(None, ge=0, le=65535)
    timeout: Optional[float] = Field(None, gt=0, le=5.0)
    grab_banners: bool = False


class PortInfo(BaseModel):
    port: int
    service: str
    banner: Optional[str] = None
    latency: Optional[float] = None


class ScanProgressResponse(BaseModel):
    scanned: int
    total: int
    open_ports: list[PortInfo]
    status: str
    elapsed: float
    progress_percent: float = 0.0


class ScanHistoryEntry(BaseModel):
    id: str
    target: str
    profile: str
    start_port: int
    end_port: int
    open_ports_count: int
    elapsed: float
    timestamp: str
    status: str


class ExportFormat(str, Enum):
    json = "json"
    csv = "csv"
    txt = "txt"
