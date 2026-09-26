from pathlib import Path

from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    binary_path: Path = (
        Path(__file__).resolve().parent.parent / "backend" / "bin" / "arpoison.bin"
    )
    default_timing_ms: int = 2000
    process_stop_timeout: float = 5.0
    startup_parse_timeout: float = 15.0
    host: str = "0.0.0.0"
    port: int = 8080

    model_config = {"env_prefix": "ARPOISON_"}
