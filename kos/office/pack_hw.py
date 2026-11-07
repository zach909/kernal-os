"""pack_hw: products that need hardware, sensors, audio/video, a network, other machines or a secure element.

None of these can be built as a sandboxed KOS app, so every entry is `none` with a plain reason."""

from __future__ import annotations

from .packkit import none

ENTRIES: list = [
    none("Camera and Photo Booth",
         "Needs a camera. KOS apps never open devices and the command protocol carries only text and pixels, "
         "so there is no way to get a frame in. Nothing covers it today."),
    none("Screen Capture and Recording",
         "Apps cannot read the screen or other apps by design; capture would break the security model. "
         "Screen Capture Tool is also not built, and nothing else covers recording."),
    none("Voice and Speech",
         "Needs a microphone, speakers and a speech model; apps get no audio device. Speech Recognition Tool "
         "and Text-to-Speech Tool are not built either, so nothing covers it today."),
    none("Audio and Video Playback",
         "Needs audio and video output devices and decoders; apps get none, and the protocol carries only "
         "text and pixels. Nothing covers playback today."),
    none("Calls and Conferencing",
         "Needs live audio and video, a network and other machines. Every connection is blocked by default and "
         "no firewall exists yet. Video Conferencing Tool covers only scheduling, roster, agenda and notes."),
    none("Remote Access and Screen Sharing",
         "Needs a network, another machine and reading the screen. Apps cannot read the screen, every connection "
         "is blocked by default, no firewall exists yet and nothing is encrypted yet. Nothing covers it."),
    none("Spatial Tracking and Calibration",
         "Needs motion, position or depth sensors and calibration of real devices. Apps never open devices and "
         "the command protocol carries only text and pixels. Nothing covers it today."),
    none("Immersive and Mixed Reality",
         "Needs a headset, tracking sensors, cameras and a 3D display pipeline. Apps get no devices and send "
         "only text and pixels to the OS. Nothing covers it today."),
    none("Payments and Digital Keys",
         "Storing payment credentials, contactless payment and digital keys need a secure element and encryption "
         "KOS does not have (nothing is encrypted yet). KOS will not fake one, so none is built."),
    none("Navigation and Traffic",
         "Needs a location sensor, map data and live traffic over a network. Apps get no sensors, every "
         "connection is blocked by default and no firewall exists yet. Nothing covers it today."),
    none("Weather",
         "Needs a network and live weather data. Every connection is blocked by default and no firewall exists "
         "yet, so an app cannot fetch forecasts. Nothing covers it today."),
    none("Cloud and Device Synchronization",
         "Needs a network, a remote service and other machines; every connection is blocked by default, no "
         "firewall exists yet and nothing is encrypted yet. `kos backup` keeps local copies only, not sync."),
    none("Wireless Sharing and Streaming",
         "Needs radio hardware (Wi-Fi, Bluetooth), a network and other devices. Apps never open devices and "
         "every connection is blocked by default. Nothing covers it today."),
    none("Accessibility Services",
         "Screen reader, magnifier, voice control, text-to-speech and speech recognition need audio devices and "
         "OS-level access that apps do not get. Text-to-Speech Tool and Speech Recognition Tool are not built."),
]
