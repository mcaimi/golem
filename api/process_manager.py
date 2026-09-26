import asyncio
import re
import signal
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone

from .config import Settings
from .models import (
    GratuitousArpRequest,
    InstanceStatus,
    SpooferInstance,
    SpooferStartRequest,
)

ANSI_ESCAPE = re.compile(r"\x1b\[[0-9;]*m")
LOCAL_INFO = re.compile(
    r"\[Core\]: Local IP: \{(.+?)\} - Local MAC: \{(.+?)\}"
)
IS_AT = re.compile(r"\[Core\]: IP \{(.+?)\} is-at \{(.+?)\}")
ARP_FOOLING = re.compile(
    r"\[Core\]: ARP-fooling: \{(.+?)\} <----> \{(.+?)\} <----> \{(.+?)\}"
)
NEW_HOST_INFO = re.compile(
    r"\[Core\]: New IP: \{(.+?)\} - New MAC: \{(.+?)\}"
)
ARP_UPDATING = re.compile(
    r"\[Core\]: ARP-updating\(\d+\): \{(.+?)\} <----> \{(.+?)\}, target MAC is \{(.+?)\}"
)
MAC_FORMAT = re.compile(r"^[0-9a-f]{2}(:[0-9a-f]{2}){5}$")


def _normalize_ip(ip_str: str) -> str:
    parts = ip_str.split(".")
    if len(parts) != 4:
        return ip_str
    try:
        return ".".join(str(int(p)) for p in parts)
    except ValueError:
        return ip_str


@dataclass
class ManagedInstance:
    id: str
    process: asyncio.subprocess.Process
    mode: int
    interface: str
    timing_ms: int
    status: InstanceStatus = InstanceStatus.STARTING
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
    started_at: datetime = field(
        default_factory=lambda: datetime.now(timezone.utc)
    )
    stopped_at: datetime | None = None
    init_complete: asyncio.Event = field(default_factory=asyncio.Event)


class ProcessManager:
    def __init__(self, settings: Settings):
        self._settings = settings
        self._instances: dict[str, ManagedInstance] = {}
        self._reader_tasks: dict[str, asyncio.Task] = {}

    async def start_poison(
        self, request: SpooferStartRequest
    ) -> tuple[str, int]:
        instance_id = str(uuid.uuid4())

        cmd = [
            str(self._settings.binary_path),
            "-i",
            request.interface,
            "-m",
            "0",
            "-t",
            str(request.timing_ms),
            str(request.victim1_ip),
            str(request.victim2_ip),
        ]

        process = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )

        instance = ManagedInstance(
            id=instance_id,
            process=process,
            mode=0,
            interface=request.interface,
            timing_ms=request.timing_ms,
            victim1_ip=str(request.victim1_ip),
            victim2_ip=str(request.victim2_ip),
        )
        self._instances[instance_id] = instance

        task = asyncio.create_task(self._stdout_reader_mode0(instance))
        self._reader_tasks[instance_id] = task

        try:
            await asyncio.wait_for(
                instance.init_complete.wait(),
                timeout=self._settings.startup_parse_timeout,
            )
        except asyncio.TimeoutError:
            if instance.process.returncode is not None:
                instance.status = InstanceStatus.FAILED
                instance.stopped_at = datetime.now(timezone.utc)
            elif instance.status == InstanceStatus.STARTING:
                instance.status = InstanceStatus.RUNNING

        return instance_id, process.pid

    async def start_gratuitous(
        self, request: GratuitousArpRequest
    ) -> tuple[str, int]:
        instance_id = str(uuid.uuid4())

        cmd = [
            str(self._settings.binary_path),
            "-i",
            request.interface,
            "-m",
            "1",
            str(request.router_ip),
            str(request.new_ip),
            request.new_mac,
        ]

        process = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )

        instance = ManagedInstance(
            id=instance_id,
            process=process,
            mode=1,
            interface=request.interface,
            timing_ms=0,
            router_ip=str(request.router_ip),
            new_ip=str(request.new_ip),
            new_mac=request.new_mac,
        )
        self._instances[instance_id] = instance

        task = asyncio.create_task(self._stdout_reader_mode1(instance))
        self._reader_tasks[instance_id] = task

        try:
            await asyncio.wait_for(
                instance.init_complete.wait(),
                timeout=self._settings.startup_parse_timeout,
            )
        except asyncio.TimeoutError:
            if instance.process.returncode is not None:
                instance.status = InstanceStatus.FAILED
                instance.stopped_at = datetime.now(timezone.utc)
            elif instance.status == InstanceStatus.STARTING:
                instance.status = InstanceStatus.RUNNING

        return instance_id, process.pid

    async def stop_instance(self, instance_id: str) -> None:
        instance = self._instances.get(instance_id)
        if instance is None:
            raise KeyError(f"Instance {instance_id} not found")

        if instance.process.returncode is not None:
            instance.status = InstanceStatus.STOPPED
            instance.stopped_at = instance.stopped_at or datetime.now(
                timezone.utc
            )
            return

        instance.status = InstanceStatus.STOPPING
        instance.process.send_signal(signal.SIGTERM)

        try:
            await asyncio.wait_for(
                instance.process.wait(),
                timeout=self._settings.process_stop_timeout,
            )
        except asyncio.TimeoutError:
            instance.process.kill()
            await instance.process.wait()

        instance.status = InstanceStatus.STOPPED
        instance.stopped_at = datetime.now(timezone.utc)

        task = self._reader_tasks.pop(instance_id, None)
        if task and not task.done():
            task.cancel()

    def get_instance(self, instance_id: str) -> SpooferInstance | None:
        instance = self._instances.get(instance_id)
        if instance is None:
            return None
        self._refresh_status(instance)
        return self._to_response(instance)

    def list_instances(self) -> list[SpooferInstance]:
        result = []
        for instance in self._instances.values():
            self._refresh_status(instance)
            result.append(self._to_response(instance))
        return result

    async def shutdown_all(self) -> None:
        tasks = []
        for instance_id, instance in self._instances.items():
            if instance.process.returncode is None:
                tasks.append(self.stop_instance(instance_id))
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)

    def _refresh_status(self, instance: ManagedInstance) -> None:
        if instance.process.returncode is not None:
            if instance.status in (
                InstanceStatus.STARTING,
                InstanceStatus.RUNNING,
            ):
                instance.status = InstanceStatus.FAILED
                instance.stopped_at = instance.stopped_at or datetime.now(
                    timezone.utc
                )

    def _to_response(self, inst: ManagedInstance) -> SpooferInstance:
        return SpooferInstance(
            id=inst.id,
            pid=inst.process.pid,
            mode=inst.mode,
            interface=inst.interface,
            status=inst.status,
            started_at=inst.started_at,
            stopped_at=inst.stopped_at,
            timing_ms=inst.timing_ms,
            victim1_ip=inst.victim1_ip,
            victim2_ip=inst.victim2_ip,
            victim1_mac=inst.victim1_mac,
            victim2_mac=inst.victim2_mac,
            attacker_ip=inst.attacker_ip,
            attacker_mac=inst.attacker_mac,
            router_ip=inst.router_ip,
            new_ip=inst.new_ip,
            new_mac=inst.new_mac,
            router_mac=inst.router_mac,
        )

    async def _stdout_reader_mode0(self, instance: ManagedInstance) -> None:
        is_at_matches: list[tuple[str, str]] = []
        try:
            while True:
                line = await instance.process.stdout.readline()
                if not line:
                    break
                text = ANSI_ESCAPE.sub(
                    "", line.decode("utf-8", errors="replace")
                ).strip()

                m = LOCAL_INFO.search(text)
                if m:
                    instance.attacker_ip = _normalize_ip(m.group(1))
                    instance.attacker_mac = m.group(2)
                    continue

                m = IS_AT.search(text)
                if m:
                    is_at_matches.append(
                        (_normalize_ip(m.group(1)), m.group(2))
                    )
                    if len(is_at_matches) == 1:
                        instance.victim1_mac = is_at_matches[0][1]
                    elif len(is_at_matches) == 2:
                        instance.victim2_mac = is_at_matches[1][1]
                    continue

                m = ARP_FOOLING.search(text)
                if m:
                    val1, val2, val3 = m.group(1), m.group(2), m.group(3)
                    if MAC_FORMAT.match(val1):
                        instance.victim1_mac = val1
                        instance.attacker_mac = val2
                        instance.victim2_mac = val3
                        instance.status = InstanceStatus.RUNNING
                        instance.init_complete.set()
                    continue
        except asyncio.CancelledError:
            pass
        finally:
            if instance.process.returncode is None:
                try:
                    await asyncio.wait_for(
                        instance.process.wait(), timeout=1.0
                    )
                except asyncio.TimeoutError:
                    pass

            if instance.status not in (
                InstanceStatus.STOPPED,
                InstanceStatus.STOPPING,
            ):
                if (
                    instance.process.returncode is not None
                    and instance.process.returncode != 0
                ):
                    instance.status = InstanceStatus.FAILED
                    instance.stopped_at = datetime.now(timezone.utc)

    async def _stdout_reader_mode1(self, instance: ManagedInstance) -> None:
        try:
            while True:
                line = await instance.process.stdout.readline()
                if not line:
                    break
                text = ANSI_ESCAPE.sub(
                    "", line.decode("utf-8", errors="replace")
                ).strip()

                m = NEW_HOST_INFO.search(text)
                if m:
                    instance.new_ip = _normalize_ip(m.group(1))
                    instance.new_mac = m.group(2)
                    continue

                m = ARP_UPDATING.search(text)
                if m:
                    instance.router_mac = m.group(3)
                    if instance.status == InstanceStatus.STARTING:
                        instance.status = InstanceStatus.RUNNING
                        instance.init_complete.set()
                    continue

                m = LOCAL_INFO.search(text)
                if m:
                    instance.attacker_ip = _normalize_ip(m.group(1))
                    instance.attacker_mac = m.group(2)
                    continue
        except asyncio.CancelledError:
            pass
        finally:
            if instance.process.returncode is None:
                try:
                    await asyncio.wait_for(
                        instance.process.wait(), timeout=5.0
                    )
                except asyncio.TimeoutError:
                    pass

            if instance.status not in (
                InstanceStatus.STOPPED,
                InstanceStatus.STOPPING,
            ):
                if instance.process.returncode is not None:
                    instance.status = InstanceStatus.STOPPED
                    instance.stopped_at = datetime.now(timezone.utc)
