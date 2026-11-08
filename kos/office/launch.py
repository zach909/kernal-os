"""Entry point for every suite app: `entry("document-editor")`, or for the extra
packs `entry("clock", "pack_time")`. Packs are imported one at a time, so an app
loads only its own code."""

from __future__ import annotations


def entry(name: str, pack: str = "") -> None:
    from kos.sdk import App

    from .ui import AppHost, run

    host = AppHost(App())
    if pack:
        import importlib
        e = next(x for x in importlib.import_module("kos.office." + pack).ENTRIES if x.name == name)
        root = e.args["make"](host, e)
    else:
        from .catalog import BY_NAME, build
        e = BY_NAME[name]
        root = build(host, e)

    def agent():
        # Ctrl-N opens the one box: commands, files and the assistant (kos/office/finder.py)
        from .agent import Agent
        from .findscreen import Finder

        def assistant(text):
            a = Agent(host, e.title, e.note)
            if text: a.submit(text)
            return a
        return Finder(host, e.title, assistant)
    run(host, root, agent=agent)
