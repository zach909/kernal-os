"""Sensors the OS can read for an app: smell, heat, humidity, pressure, light.

Linux exposes plain sensors (temperature, humidity, pressure, light, gas) as small text files under
``/sys/bus/iio/devices/iio:deviceN/``. This reads a fixed list of those files and nothing else: no serial
numbers, no addresses, no device node under ``/dev``. Every reading is turned into a whole number
without ever being a float (``to_milli`` works on the digits), and an app that asks for them gets them
only through the ``sensor`` service group, after the owner types the password for that read.

What a reading means is not known here. A "smell" channel is a gas sensor's resistance in ohms: a number
that moves when volatile compounds change, not a name for any smell. Tell Atlas where each sensor sits and
it can compare sensors and find where a change comes from; it cannot say what the smell is.

Reading a sysfs attribute is not opening a device (see the kos-hardware skill), but the files behind
``iio:deviceN`` are reached through a symlink the kernel makes; only the fixed names below are ever opened.
"""

from __future__ import annotations

import os
import re
import time
from dataclasses import dataclass
from pathlib import Path

IIO = Path("/sys/bus/iio/devices")
DEVICE_RE = re.compile(r"^iio:device([0-9]{1,3})$")
NUMBER_RE = re.compile(r"^[+-]?[0-9]{1,15}(\.[0-9]{1,9})?$")
MAX_ATTR = 64                  # bytes read from one attribute
MAX_DEVICES = 64


class SensorError(Exception):
    pass


@dataclass(frozen=True)
class Channel:
    attr: str          # the file name, always one of ``CHANNELS``
    kind: str          # smell, heat, humidity, pressure, light
    unit: str          # what the whole number counts
    milli: bool        # the file holds a decimal in a bigger unit: keep three digits of it, as a whole number


# The whole list. A channel not here is never opened. Units are what the whole number counts.
CHANNELS = (
    Channel("in_temp_input", "heat", "mC", False),                 # IIO: milli-degrees Celsius
    Channel("in_humidityrelative_input", "humidity", "m%", False),  # IIO: milli-percent
    Channel("in_pressure_input", "pressure", "Pa", True),          # IIO: kilopascal, a decimal: x1000 = pascal
    Channel("in_illuminance_input", "light", "mlux", True),        # IIO: lux, a decimal
    Channel("in_resistance_raw", "smell", "ohm", False),           # a gas sensor's resistance (a VOC proxy)
    Channel("in_concentration_raw", "smell", "raw", False),        # a gas or VOC concentration, driver units
    Channel("in_concentration_voc_raw", "smell", "raw", False),
)
BY_ATTR = {c.attr: c for c in CHANNELS}


def to_milli(text: str) -> int:
    """A decimal such as ``101.325`` as the whole number 101325, using only its digits. The tail beyond
    three places is cut, not rounded. Anything that is not a plain decimal raises ``SensorError``."""
    t = text.strip()
    if not NUMBER_RE.match(t):
        raise SensorError("not a number")
    sign = -1 if t.startswith("-") else 1
    t = t.lstrip("+-")
    whole, _, frac = t.partition(".")
    return sign * (int(whole) * 1000 + int((frac + "000")[:3]))


def to_whole(text: str) -> int:
    """A reading that must already be a whole number."""
    t = text.strip()
    if not re.match(r"^[+-]?[0-9]{1,15}$", t):
        raise SensorError("not a whole number")
    return int(t)


def _read_attr(path: Path) -> str:
    try:
        if not path.is_file():
            raise SensorError("missing")
        with open(path, "rb") as f:
            raw = f.read(MAX_ATTR + 1)
    except OSError as e:
        raise SensorError(str(e.strerror or "unreadable")) from None
    if len(raw) > MAX_ATTR:
        raise SensorError("too long")
    return raw.decode("ascii", "replace")


def _device_dirs(root: Path) -> list:
    try:
        names = sorted(os.listdir(root))
    except OSError:
        return []
    out = []
    for n in names:
        m = DEVICE_RE.match(n)
        if m:
            out.append((int(m.group(1)), root.joinpath(n)))
    return out[:MAX_DEVICES]


def list_sensors(root: Path | None = None) -> list:
    """``[{"index": N, "name": ..., "channels": [{"attr", "kind", "unit"}]}]`` for what is plugged in."""
    out = []
    for index, d in _device_dirs(root or IIO):
        try:
            name = _read_attr(d.joinpath("name")).strip()[:40] or "sensor"
        except SensorError:
            name = "sensor"
        chans = [{"attr": c.attr, "kind": c.kind, "unit": c.unit} for c in CHANNELS if d.joinpath(c.attr).is_file()]
        if chans:
            out.append({"index": index, "name": name, "channels": chans})
    return out


def read_sensor(index: int, root: Path | None = None) -> dict:
    """All of one device's known channels, as whole numbers, and the time in whole seconds.
    A channel that cannot be read or parsed is left out and counted in ``skipped``."""
    for i, d in _device_dirs(root or IIO):
        if i != index:
            continue
        readings, skipped = [], 0
        for c in CHANNELS:
            if not d.joinpath(c.attr).is_file():
                continue
            try:
                text = _read_attr(d.joinpath(c.attr))
                v = to_milli(text) if c.milli else to_whole(text)
            except SensorError:
                skipped += 1
                continue
            readings.append({"attr": c.attr, "kind": c.kind, "unit": c.unit, "v": v})
        return {"index": index, "t": time.time_ns() // 1_000_000_000, "readings": readings, "skipped": skipped}
    raise SensorError("no such sensor")


def sweep(root: Path | None = None) -> dict:
    """Every sensor's readings in one go: ``{"t": seconds, "sensors": [{"index", "name", "readings", "skipped"}]}``."""
    out = []
    t = time.time_ns() // 1_000_000_000
    for info in list_sensors(root):
        r = read_sensor(info["index"], root)
        out.append({"index": info["index"], "name": info["name"], "readings": r["readings"], "skipped": r["skipped"]})
    return {"t": t, "sensors": out}
