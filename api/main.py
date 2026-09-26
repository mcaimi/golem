import logging
import os
from contextlib import asynccontextmanager

from fastapi import FastAPI

from .config import Settings
from .process_manager import ProcessManager
from .routes import init_router, router

logger = logging.getLogger("arpoison-api")

settings = Settings()
process_manager = ProcessManager(settings)
init_router(settings, process_manager)


@asynccontextmanager
async def lifespan(app: FastAPI):
    if os.getuid() != 0:
        logger.warning(
            "API server is NOT running as root; arpoison.bin will fail to launch"
        )
    if not settings.binary_path.is_file():
        logger.warning(
            "arpoison.bin not found at %s", settings.binary_path
        )
    logger.info("ARP Poison API starting up")

    yield

    logger.info("Shutting down: terminating all running spoofer instances")
    await process_manager.shutdown_all()


app = FastAPI(
    title="ARP Poison API",
    description="REST API for managing ARP spoofing MITM instances",
    version="0.1.0",
    lifespan=lifespan,
)

app.include_router(router)
