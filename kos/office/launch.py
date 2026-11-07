"""Entry point for every suite app: `entry("document-editor")`."""

from __future__ import annotations


def entry(name: str) -> None:
    from kos.sdk import App

    from .catalog import BY_NAME, build
    from .ui import AppHost, run

    e = BY_NAME[name]
    host = AppHost(App())
    run(host, build(host, e))
