import os

from fastapi import APIRouter, HTTPException, status

from .config import Settings
from .models import (
    ErrorResponse,
    GratuitousArpRequest,
    HealthResponse,
    InstanceStatus,
    SpooferListResponse,
    SpooferStartRequest,
    SpooferStartResponse,
    SpooferStopResponse,
    SpooferInstance,
)
from .process_manager import ProcessManager

router = APIRouter(prefix="/api/v1", tags=["spoofer"])

settings: Settings | None = None
process_manager: ProcessManager | None = None


def init_router(s: Settings, pm: ProcessManager) -> None:
    global settings, process_manager
    settings = s
    process_manager = pm


@router.post(
    "/spoofer",
    response_model=SpooferStartResponse,
    status_code=status.HTTP_201_CREATED,
    responses={400: {"model": ErrorResponse}, 500: {"model": ErrorResponse}},
)
async def start_spoofer(request: SpooferStartRequest):
    try:
        instance_id, pid = await process_manager.start_poison(request)
    except FileNotFoundError:
        raise HTTPException(
            status_code=500, detail="arpoison.bin binary not found"
        )
    except PermissionError:
        raise HTTPException(
            status_code=500,
            detail="Insufficient privileges to execute arpoison.bin",
        )

    return SpooferStartResponse(
        id=instance_id,
        pid=pid,
        status=InstanceStatus.STARTING,
        message="Spoofer instance launched; MAC resolution in progress",
    )


@router.post(
    "/spoofer/gratuitous",
    response_model=SpooferStartResponse,
    status_code=status.HTTP_201_CREATED,
    responses={400: {"model": ErrorResponse}, 500: {"model": ErrorResponse}},
)
async def start_gratuitous_arp(request: GratuitousArpRequest):
    try:
        instance_id, pid = await process_manager.start_gratuitous(request)
    except FileNotFoundError:
        raise HTTPException(
            status_code=500, detail="arpoison.bin binary not found"
        )
    except PermissionError:
        raise HTTPException(
            status_code=500,
            detail="Insufficient privileges to execute arpoison.bin",
        )

    return SpooferStartResponse(
        id=instance_id,
        pid=pid,
        status=InstanceStatus.STARTING,
        message="Gratuitous ARP instance launched",
    )


@router.get("/spoofer", response_model=SpooferListResponse)
async def list_spoofers():
    instances = process_manager.list_instances()
    return SpooferListResponse(instances=instances, count=len(instances))


@router.get(
    "/spoofer/{instance_id}",
    response_model=SpooferInstance,
    responses={404: {"model": ErrorResponse}},
)
async def get_spoofer(instance_id: str):
    instance = process_manager.get_instance(instance_id)
    if instance is None:
        raise HTTPException(
            status_code=404, detail=f"Instance {instance_id} not found"
        )
    return instance


@router.delete(
    "/spoofer/{instance_id}",
    response_model=SpooferStopResponse,
    responses={404: {"model": ErrorResponse}, 409: {"model": ErrorResponse}},
)
async def stop_spoofer(instance_id: str):
    instance = process_manager.get_instance(instance_id)
    if instance is None:
        raise HTTPException(
            status_code=404, detail=f"Instance {instance_id} not found"
        )

    if instance.status in (InstanceStatus.STOPPED, InstanceStatus.FAILED):
        raise HTTPException(
            status_code=409,
            detail=f"Instance {instance_id} already {instance.status}",
        )

    await process_manager.stop_instance(instance_id)

    return SpooferStopResponse(
        id=instance_id,
        pid=instance.pid,
        status=InstanceStatus.STOPPED,
        message="Spoofer instance terminated",
    )


@router.get("/health", response_model=HealthResponse, tags=["system"])
async def health_check():
    running = sum(
        1
        for inst in process_manager.list_instances()
        if inst.status == InstanceStatus.RUNNING
    )
    return HealthResponse(
        status="ok",
        running_instances=running,
        is_root=os.getuid() == 0,
        binary_exists=settings.binary_path.is_file(),
    )
