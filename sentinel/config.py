import os

from dotenv import load_dotenv

load_dotenv()


def required(name: str) -> str:
    value = os.environ.get(name)
    if not value:
        raise RuntimeError(f"missing required env var: {name} (set it in .env or shell)")
    return value


def optional(name: str, default: str | None = None) -> str | None:
    return os.environ.get(name) or default
