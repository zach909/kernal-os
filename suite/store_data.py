"""The Store catalogue: every function in docs/REQUESTED_DEFAULT_APPS (the user's per-device list), merged
by what it *does* (rule 6: one app per function), with the devices that ship it and an honest scope.

scope  full     does the whole job as a single-user, offline app
       partial  does a real, useful part of it (the note says what is missing)
       shell    a screen that says what the app is for and why it cannot do it yet; no pretend behaviour

Whole numbers only (rule 1): this file holds text and small integers."""

DEVICES = {"AND": "Android phone", "IOS": "iPhone (iOS)", "MAC": "Mac (macOS)", "WIN": "Windows 11",
           "LIN": "Linux desktop", "VIS": "Apple Vision Pro", "GVR": "Google VR (historical)",
           "GLS": "Google Glass (historical)", "IGL": "iGlasses (proposed concept, not a real product)"}

NEEDS = {
    "net": "network access. Every connection is blocked by default; this app would need a manifest permission and a firewall rule for one host, port and protocol, plus a service to talk to",
    "cam": "a camera. Apps never open devices; the OS would have to read one and hand frames over, and no command does that yet",
    "aud": "a microphone or speaker. Apps never open devices and KOS has no audio command yet",
    "sens": "motion, compass or location sensors. Apps never open devices and KOS has no sensor command yet",
    "radio": "radio hardware (Wi-Fi, Bluetooth, cellular). Only the OS may touch hardware and it exposes no such command to apps yet",
    "gfx": "3D, augmented or virtual-reality display. KOS draws a text screen and a 2D canvas only",
    "osread": "system state (processes, disks, logs, drivers, updates). No OS service reads these for an app yet",
    "acct": "an online account and the service behind it, which this repository does not provide",
    "file": "files outside the app's own storage. That needs a service with a password prompt, which is not built for this",
    "media": "decoding and playing audio or video. KOS has no media decoder and no audio command",
    "ai": "a model. The built-in agent is a separate app and an app cannot hand it a question",
}

# id, title, archetype, devices, needs-key (shell only), what it is for, pointer (optional), note for the catalogue
E = []


def add(i, title, arch, dev, needs="", does="", see="", note=""):
    E.append(dict(id=i, title=title, arch=arch, dev=dev.split(), needs=needs, does=does, see=see, note=note))


ALL = "AND IOS MAC WIN LIN VIS GVR GLS IGL"
# --- apps that do a real, offline job -------------------------------------------------------------------
add("calculator", "Calculator", "calc", "AND IOS MAC WIN LIN",
    does="Exact arithmetic: + - * / and brackets on whole numbers and fractions; answers are shown as 7/2, never 3.5.",
    note="Exact fractions only, no decimals (rule 6). No scientific functions, no memory.")
add("clock", "Clock", "clock", "AND IOS MAC WIN LIN IGL",
    does="UTC time and date, a world clock in whole and half-hour offsets, and a stopwatch.",
    note="Shows the time when you press a key: an app gets no clock ticks, so it does not count live. No alarms or timers.")
add("calendar", "Calendar", "calendar", "AND IOS MAC WIN LIN VIS GLS IGL",
    does="A month grid for any year, today marked, with left/right for months and up/down for years.",
    note="Dates only: no events, invitations or accounts. Uses UTC for 'today'.")
add("contacts", "Contacts", "contacts", "AND IOS MAC GLS IGL VIS",
    does="Name, phone and email records kept in the app's own storage.",
    note="Local only: no sync, groups, photos or merging. Not shared with other apps (no shared folder).")
add("notes", "Notes", "notes", "AND IOS MAC WIN VIS",
    does="Short text notes kept in the app's own storage: add, read, delete.",
    note="Plain text, 400 characters per note, 200 notes. No formatting, folders, search or sync.")
add("text-editor", "Text Editor", "notes", "MAC WIN LIN",
    does="Scratch text buffers (Text Editor, Notepad and TextEdit are one function).",
    note="Stored in the app's own storage, not as files: it cannot open or save a file on disk (needs a file service).")
add("journal", "Journal", "notes", "IOS",
    does="Dated diary entries: each is stamped with today's UTC date.",
    note="Plain text, no photos, places, prompts or reminders.")
add("reminders", "Reminders", "checklist", "IOS MAC VIS IGL",
    does="A checklist: add items, tick them off, delete them.",
    note="No due dates, alerts, lists or repeats: nothing here can wake an app at a time.")
add("passwords", "Passwords", "secrets", "IOS MAC LIN",
    does="Keeps name/secret pairs in the OS's own passwords store (the 'passwords' permission). Secrets are hidden until you press enter.",
    note="The OS keeps them in clear on the LUKS volume today (README gaps table, rule 8). No autofill, no generator, no breach checks.")
add("characters", "Characters", "chars", "WIN LIN MAC",
    does="Browse Unicode by code point with names (Character Map, Characters and the character viewer are one function).",
    note="Browse only: it cannot paste into another app. Names come from Python's Unicode database.")
add("unit-converter", "Unit Converter", "units", "IOS",
    does="Converts length, mass and temperature exactly, as fractions.",
    note="Three families only. Not the camera ruler that Measure is (see `measure`).")
add("app-store", "App Store", "catalog", "AND IOS WIN LIN GVR",
    does="Lists every app in the Store with what it does and how much of the job it really does.",
    note="A list only: it cannot install anything (`kos install` asks the password; no service lets an app do that).")

# --- screens that cannot do their job yet ---------------------------------------------------------------
S = add
S("phone", "Phone", "info", "AND IOS WIN GLS IGL", "radio", "Place and answer calls.", note="Needs a modem and audio.")
S("messages", "Messages", "info", ALL.replace("LIN ", "").replace("WIN ", ""), "net", "Send and read text messages and chats.")
S("video-calls", "Video Calls", "info", "AND IOS WIN GLS", "net", "Video calling (FaceTime, Meet, Teams, Video Calling are one function).")
S("mail", "Mail", "info", "AND IOS MAC WIN LIN VIS", "net", "Read and write email (Mail, Gmail, Outlook and Thunderbird are one function).", see="`email-client` in the productivity suite (`bin/suite list`) is a local mail app with no network")
S("browser", "Browser", "info", "AND IOS MAC WIN LIN VIS GVR", "net", "Browse websites (Chrome, Safari, Edge, Firefox and the VR browser are one function).", see="`examples/web` is KOS's own text browser: https only, certificates checked, firewall rule per host")
S("search", "Search", "info", "GLS IGL", "net", "Search the web by typing or speaking.", see="Ctrl-N in any suite app, or `/` in the App Library, searches installed apps, commands and files (never the web)")
S("camera", "Camera", "info", "AND IOS MAC WIN LIN VIS GLS IGL", "cam", "Take photos and video (Camera, Photo Booth, Photo and Video Capture are one function).")
S("photos", "Photos", "info", "AND IOS MAC WIN LIN VIS GVR", "media", "View and organise pictures (Photos, Preview, Image Viewer, Shotwell, VR Photos).", note="`Canvas.image` can draw pixels, but there is no image decoder app yet.")
S("video-player", "Video Player", "info", "MAC WIN LIN GVR IGL", "media", "Play video (QuickTime Player, Media Player, Videos, VR Cinema and Videos).")
S("tv", "TV", "info", "AND IOS MAC VIS", "net", "Watch shows and films from a streaming service (Apple TV, Google TV, TV).")
S("youtube", "YouTube", "info", "AND GVR", "net", "Watch video from YouTube (YouTube and YouTube VR).")
S("music", "Music", "info", "AND IOS MAC WIN LIN VIS IGL", "media", "Play a music library and streams (Music, YouTube Music, Rhythmbox).")
S("podcasts", "Podcasts", "info", "IOS MAC VIS IGL", "net", "Follow and play podcasts.")
S("books", "Books", "info", "IOS MAC VIS", "acct", "Read books and listen to audiobooks.")
S("news", "News", "info", "AND IOS MAC VIS", "net", "Read headlines.")
S("stocks", "Stocks", "info", "IOS MAC VIS", "net", "Watch share prices.")
S("weather", "Weather", "info", "IOS MAC IGL", "net", "Forecasts for your places.")
S("maps", "Maps", "info", "AND IOS MAC WIN GLS IGL VIS", "net", "Maps and directions (Maps, Google Maps, Directions).")
S("navigation", "Navigation", "info", "GLS IGL", "sens", "Turn-by-turn guidance while you move.", note="Needs location sensors and a map source.")
S("street-view", "Street View", "info", "GVR", "net", "Look around streets in 360 degrees.")
S("translate", "Translate", "info", "IOS GLS IGL", "net", "Translate text and speech (Translate, Translation).")
S("voice-assistant", "Voice Assistant", "info", "AND IOS MAC GLS IGL", "ai", "Answer spoken requests (Siri, Google Assistant, Gemini, Voice Commands).", see="The built-in agent (`kos agent`) is KOS's assistant; it works on this computer's model only")
S("voice-memos", "Voice Memos", "info", "AND IOS MAC WIN", "aud", "Record and play back short audio.")
S("live-captions", "Live Captions", "info", "IGL", "aud", "Show speech as text as it happens.")
S("visual-search", "Visual Search", "info", "IGL", "cam", "Recognise objects and read text the camera sees (Visual Search, Object and Text Recognition).")
S("magnifier", "Magnifier", "info", "IOS", "cam", "Zoom in on what the camera sees.")
S("measure", "Measure", "info", "IOS", "cam", "Measure real objects with the camera and motion sensors.", see="`unit-converter` converts units exactly, but does not measure anything")
S("compass", "Compass", "info", "IOS", "sens", "Show which way you face.")
S("wallet", "Wallet", "info", "AND IOS", "acct", "Cards, passes and payments.", note="A wallet is a payment surface: not built, and not something to fake.")
S("health", "Health", "info", "IOS", "sens", "Health records and measurements.")
S("fitness", "Fitness", "info", "IOS", "sens", "Activity and workout tracking.")
S("find-my", "Find My", "info", "IOS MAC", "net", "Locate your devices.")
S("safety", "Safety", "info", "AND", "radio", "Emergency contacts, check-ins and SOS.")
S("device-health", "Device Health Services", "info", "AND", "osread", "Report battery, storage and device health.")
S("freeform", "Freeform", "info", "IOS MAC VIS", "gfx", "A free-form whiteboard of text, shapes and pictures.", note="Needs pointer drawing on a 2D canvas; the canvas exists but no whiteboard app does yet.")
S("paint", "Paint", "info", "WIN", "gfx", "Draw and edit pictures.")
S("shortcuts", "Shortcuts", "info", "IOS MAC VIS", "osread", "Chain actions of other apps into a shortcut (Shortcuts, Automator).", note="Apps never call each other (soft rule), so this would need a design of its own.")
S("script-editor", "Script Editor", "info", "MAC", "osread", "Write and run automation scripts.", note="Anything that runs code must pass the proof gate; a script runner would need its own design.")
S("files", "Files", "info", "AND IOS MAC WIN LIN VIS", "file", "Browse and manage files (Files, Finder, File Explorer).", see="`kos ls`, `kos cat` and `kos explore`")
S("cloud-drive", "Cloud Drive", "info", "AND WIN", "acct", "Files kept online (Google Drive, OneDrive).")
S("document-viewer", "Document Viewer", "info", "MAC LIN", "file", "Read PDFs and documents (Preview, Document Viewer).")
S("document-scanner", "Document Scanner", "info", "LIN", "cam", "Scan paper into a file.")
S("archive-manager", "Archive Manager", "info", "LIN", "file", "Open and make zip and tar archives.")
S("screenshot", "Screenshot", "info", "MAC WIN LIN", "osread", "Capture the screen (Screenshot, Snipping Tool).", note="The trusted password overlay must never be capturable by an app, so this is the OS's decision.")
S("fonts", "Fonts", "info", "MAC LIN", "osread", "Browse installed fonts (Font Book, Fonts).")
S("task-manager", "Task Manager", "info", "MAC WIN LIN", "osread", "Show running programs and their load (Activity Monitor, Task Manager, System Monitor, Resource Monitor).", see="`kos activity` and the System Information app (`apps/kernel`)")
S("disk-utility", "Disk Utility", "info", "MAC WIN LIN", "osread", "Inspect and repair disks (Disk Utility, Disks, Disk Management, Disk Usage Analyzer).")
S("logs", "Logs", "info", "MAC LIN", "osread", "Read system logs (Console, Logs).", see="`kos audit --verify` for the OS audit log")
S("startup-apps", "Startup Applications", "info", "WIN LIN", "osread", "Choose what starts at boot (System Configuration, Startup Applications).")
S("software-updater", "Software Updater", "info", "LIN", "net", "Install updates.")
S("firmware-updater", "Firmware Updater", "info", "LIN", "radio", "Update device firmware.", see="`kos firmware` and `kos fwflash`")
S("drivers", "Additional Drivers", "info", "LIN", "osread", "Choose drivers for hardware.")
S("language-support", "Language Support", "info", "LIN", "osread", "Choose display languages and input methods.")
S("power-stats", "Power Statistics", "info", "LIN", "osread", "Show battery and power use.")
S("battery", "Battery", "info", "IGL", "osread", "Battery level and charging.")
S("settings", "Settings", "info", "AND IOS MAC WIN LIN VIS GVR GLS IGL", "osread", "The device settings screen. Each setting with a screen of its own is its own app.", see="`mouse`, `keyboard`, `display` and `wallpaper` are KOS's setting apps today")
S("wifi", "Wi-Fi", "info", "GLS", "radio", "Join Wi-Fi networks (Wi-Fi Setup).")
S("bluetooth", "Bluetooth", "info", "GLS", "radio", "Pair Bluetooth devices (Bluetooth Setup).")
S("device-setup", "Device Setup", "info", "GLS", "osread", "First-run setup of a device.")
S("device-pairing", "Device Pairing", "info", "IGL", "radio", "Pair accessories.", see="`device-chooser` boots the mouse and keyboard with the password")
S("privacy-controls", "Privacy Controls", "info", "IGL", "osread", "Choose which apps may use which parts of the device.", see="`kos permit`, `kos grant` and `kos secure`")
S("security-center", "Security Center", "info", "WIN", "osread", "Virus and threat status (Windows Security).", see="`kos secure` and the install-time scanner")
S("notifications", "Notifications", "info", "GLS IGL", "osread", "Show alerts from apps.", note="Apps never call each other, so a notification centre needs its own design.")
S("game-bar", "Game Bar", "info", "WIN", "gfx", "Overlay for capture and game stats (Xbox Game Bar).")
S("remote-desktop", "Remote Desktop", "info", "WIN LIN", "net", "Control another computer (Quick Assist, Remote Desktop, Remmina).")
S("bittorrent", "BitTorrent", "info", "LIN", "net", "Download files over BitTorrent (Transmission).")
S("feedback", "Feedback", "info", "WIN", "net", "Send feedback to the maker (Feedback Hub).")
S("help", "Help", "info", "WIN LIN", "osread", "Help and tips (Get Help, Help, Tips).", see="`kos help` and `kos skills`")
S("tips", "Tips", "info", "IOS MAC WIN VIS", "osread", "Short lessons on using the device.", see="`kos help`")
S("mindfulness", "Mindfulness", "info", "VIS", "gfx", "Guided breathing and reflection.")
S("encounter-dinosaurs", "Encounter Dinosaurs", "info", "VIS", "gfx", "A 3D augmented-reality demo.")
S("vr-home", "VR Home", "info", "GVR", "gfx", "The headset's home space.")
S("vr-games", "VR Games", "info", "GVR", "gfx", "Games for a headset.")
S("vr-experiences", "VR Experiences", "info", "GVR", "gfx", "Guided 360-degree experiences.")
S("vr-controller-setup", "VR Controller Setup", "info", "GVR", "radio", "Pair and calibrate the hand controller.")
S("vr-tutorial", "VR Tutorial", "info", "GVR", "gfx", "A first-use walkthrough for a headset.")

# Functions in the list that already exist in KOS, so the Store does not make a second copy (rule 6).
COVERED = [
    ("Display Controls (Glass, iGlasses)", "`display`", "apps/display"),
    ("Smart Home (Google Home, Apple Home)", "`home.devices`, `home.pair`, `home.control`", "apps/home"),
    ("Terminal, Command Prompt, PowerShell, Windows Terminal", "`terminal`", "productivity suite (`kos/office/pack_system.py`)"),
    ("System Information", "System Information (`kernel`)", "apps/kernel"),
    ("Time Machine, Windows Backup, Backups", "`backup`", "apps/backup"),
    ("Migration Assistant", "`migrate`", "apps/migrate"),
    ("Phone Link", "the linked-device apps (`sync.*`)", "apps/sync"),
    ("Microsoft 365, LibreOffice Writer, Calc, Impress, Draw, Math, Keynote", "the productivity suite", "`bin/suite list`"),
]
