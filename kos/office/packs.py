"""The extra packs: one module per group, each exporting ENTRIES (see packkit)."""

from __future__ import annotations

import importlib

PACKS = ["pack_time", "pack_calc", "pack_learn", "pack_health", "pack_personal", "pack_geo", "pack_audio",
         "pack_media", "pack_devvc", "pack_devutil", "pack_ml", "pack_biz1", "pack_biz2", "pack_games",
         "pack_os", "pack_hw", "pack_tour", "pack_neuro", "pack_org"]


def entries() -> list:
    out = []
    for p in PACKS:
        for e in importlib.import_module("kos.office." + p).ENTRIES:
            e.pack = p
            out.append(e)
    return out
