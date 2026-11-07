"""pack_tour: "Get to Know KOS" - ten short quiz games, one per part of the operating system.

One question bank (PARTS) and one generic game screen (Game); nothing else. Every fact is checked against the
code by tests/test_pack_tour.py. No timers, no network, nothing in the background."""

from __future__ import annotations

import random

from .packkit import app
from .ui import ListNav, Screen, Store, wrap

# A question: (text, the right choice, (wrong choices...), one-line explanation).
# Writing rule: state only what is built today (README rules + the gaps table). Say "not yet" where it is a gap.
Q = tuple

PIPELINE = (
    ("What does an app send to the OS to put something on the screen?", "screen or frame commands",
     ("key commands", "pointer commands", "direct writes to the framebuffer"),
     "Apps only send commands (screen, frame). The OS checks them and draws; apps never touch the screen hardware."),
    ("Which commands carry your input to the app?", "key, pointer and button",
     ("screen and frame", "evdev reads", "request and permit"),
     "The OS reads the devices and sends key, pointer and button commands to the app."),
    ("Who reads the keyboard and mouse devices (evdev)?", "The OS, never the app",
     ("The app, once it has a permit", "The sandbox's seccomp filter", "The app library"),
     "Apps never touch the kernel or hardware; only the OS does."),
    ("Which list runs in order from what you see down to the metal?", "screen, app, OS, kernel, hardware",
     ("screen, OS, app, kernel, hardware", "app, screen, kernel, OS, hardware", "hardware, app, OS, kernel, screen"),
     "README rule 4: screen <- frame/screen <- app <- key/pointer/button <- OS <- kernel <- hardware."),
    ("Is the command channel between app and OS encrypted today?", "No: plain JSON lines over a socket",
     ("Yes, with authenticated encryption", "Yes, but only the screen commands", "Only inside a kernel cell"),
     "Rule 4 says it should be; the README gaps table says nothing is encrypted yet. Not done."),
    ("Who draws the password prompt?", "The OS, as an overlay the app cannot see or cover",
     ("The app that asked for it", "The taskbar app", "The app's sandbox"),
     "That is why a hostile app cannot fake or read your password prompt."),
)

PASSWORD = (
    ("You type run hello for the tenth time today. Does KOS ask for the password?", "Yes, on every launch",
     ("No, the first time covered it", "Only after a reboot", "Only if the app uses the network"),
     "KOS has no cached logins: every action needs the password typed for that action (app.run)."),
    ("Which action asks for your password when you let an app use the mouse?", "device.mouse",
     ("app.install", "file.view", "session.login"),
     "Booting a device is its own action; the keyboard is device.keyboard."),
    ("What does the audit log keep of each password decision?", "A hash-chained record you can check with kos audit --verify",
     ("Nothing, decisions are not logged", "A file the app can edit", "Only the wrong passwords"),
     "Granted, denied and cancelled decisions are recorded, and tampering shows up when verified."),
    ("Which of these need no password today?", "kos list, kos ps, kos ls, kos doctor",
     ("kos run, kos open, kos install, kos remove", "kos grant, kos passwd, kos permit, kos backup",
      "kos view, kos write, kos update, kos optimize"),
     "The README gaps table lists the open ones. Some show private state (audit, activity); that is a known gap."),
    ("Which action protects changing your password?", "auth.change",
     ("session.login", "app.permit", "admin.boot"),
     "Even changing the password goes through Authority.authorize."),
    ("Taking an app's shared-folder access away again uses which action?", "space.revoke",
     ("app.revoke", "app.remove", "app.update"),
     "app.revoke takes away permission to run; space.revoke takes away a shared folder."),
    ("Does kos security need a password?", "No, it is read-only and changes nothing",
     ("Yes, always", "Yes, but only the first time", "It needs the administrator keyboard"),
     "It only checks what KOS can verify about itself and exits 3 if anything failed."),
)

SANDBOX = (
    ("An app tries to read your files. What stops it?", "Landlock; the app also runs as nobody",
     ("Nothing, apps may read files", "The virus scanner at run time", "The audit log"),
     "Apps run under Landlock plus namespaces: no reading your files, no writing."),
    ("An app without the network permission tries to connect. What stops it?", "Its empty network namespace",
     ("The virus scanner", "The password prompt", "Nothing, only the browser is blocked"),
     "No network unless you allow it with your password."),
    ("When an app runs, is its zip unzipped onto the disk?", "No: it is copied into a sealed in-RAM file and run from there",
     ("Yes, into a temporary folder", "Yes, into your home folder", "Only for graphical apps"),
     "Apps are zip files that are never unzipped; the run uses a memfd copy."),
    ("You edit an installed app's zip. What happens next time?", "It refuses to run",
     ("It runs, with a warning", "KOS repairs it quietly", "It runs but without network"),
     "The zip is sealed with a password-derived key; a modified zip fails the seal."),
    ("An app calls bpf or io_uring. What happens?", "The seccomp denylist blocks it",
     ("It works if the app has a permit", "It works inside the sandbox", "It is only logged"),
     "The seccomp filter denies bpf, io_uring, perf and keyring syscalls (x86_64)."),
    ("The kernel cannot enforce Landlock. What happens to apps?", "They do not start",
     ("They start without a sandbox", "They start read-only", "They start in a cell"),
     "KOS refuses to run apps it cannot confine."),
    ("Which limits does the sandbox set?", "1 GiB of memory and 64 MiB per file",
     ("No limits", "256 MiB of memory and 1 MiB per file", "4 GiB of memory and no file limit"),
     "These are the limits in the README."),
    ("When is an app's private cache folder removed?", "The moment the app's process ends",
     ("At the next reboot", "When you run kos optimize", "Never"),
     "The directory is overwritten and deleted on any exit."),
)

PERMITS = (
    ("What does kos permit NAME decide?", "That the app may run at all, once",
     ("That the password is skipped", "That the app is safe", "That the app may use the network forever"),
     "A permit is separate from the password and never replaces it."),
    ("An app has a permit. Does run still ask for the password?", "Yes, on every single launch",
     ("No, the permit replaces it", "Only the first launch", "Only for graphical apps"),
     "Permit says allowed to run; the password says it is really you, each time."),
    ("An update asks for a new manifest permission such as network. What happens?", "It is refused until you permit again",
     ("It installs and asks at first use", "It installs silently", "The old version is deleted"),
     "kos permit records which permissions you approved; asking for more is refused."),
    ("Which manifest permission lets an app ask the OS for system functions?", "system",
     ("storage", "network", "kernel"),
     "It also needs a permit, and opening or closing needs your password in the OS's own prompt."),
    ("Which permission does every suite app in this repo get?", "storage",
     ("network", "system", "camera"),
     "Apps keep their data in their own vault; network is declared only where an app cannot work without it."),
    ("What does the network permission give an app today?", "Every host and port, and it may listen",
     ("One host you pick", "Web pages only", "Outgoing connections on port 443 only"),
     "It is one yes or no at launch. Per-host rules need the firewall, which does not exist yet."),
    ("When is the network permission decided?", "At launch, with your password",
     ("When the app first connects", "At install time only", "Never, it is on for everyone"),
     "Decided at launch (action app.network), not at first use: a known gap."),
)

SHARED = (
    ("Which app owns the contacts folder?", "Contact Manager", ("Email Client", "CRM", "Task Manager"),
     "Other apps may look people up in it only after you grant them."),
    ("Email Client declares uses:contacts. Can it read contacts right away?", "No, not until you grant it with your password",
     ("Yes, the manifest is enough", "Yes, if the app has a permit", "Yes, read-only"),
     "The manifest has to ask and the permission store has to say yes."),
    ("Which command lets Email Client into the contacts folder?", "kos grant email-client space:contacts --level read",
     ("kos permit email-client space:contacts", "kos spaces email-client contacts", "kos dirs contacts"),
     "kos grant takes the app, space:NAME and --level read or write; it asks for your password."),
    ("Which command shows who owns each shared folder and who has access?", "kos spaces",
     ("kos dirs", "kos ls", "kos activity"),
     "kos dirs APP shows one app's own cache, data and run folders instead."),
    ("Can another app take over the name contacts once Contact Manager owns it?", "No",
     ("Yes, if it asks first", "Yes, with a permit", "Yes, after a reboot"),
     "Nobody can take over a name someone else owns."),
    ("To be let into a shared folder an app needs:", "Its manifest asks AND you granted it",
     ("Only its manifest", "Only your grant", "Only the owner's say-so"),
     "Anyone holding a grant of at least the level asked for may use it: that is the whole rule."),
    ("Which app owns the calendar folder?", "Calendar Manager", ("Task Manager", "Contact Manager", "Places"),
     "The scheduler books onto it; Task Manager owns tasks and Contact Manager owns contacts."),
    ("Which grant levels exist for a shared folder?", "read and write",
     ("read only", "owner and guest", "view, edit and delete"),
     "kos grant APP space:NAME --level read|write. The password is asked either way."),
)

BLOCKED = (
    ("What does KOS rule 3 say about connections?", "Every connection is blocked until a rule allows it",
     ("Connections are allowed unless reported", "Only the internet is blocked", "Only apps from unknown makers are blocked"),
     "Any pair, any protocol, any port. It is a rule every change must meet."),
    ("Does KOS have a firewall today?", "No: it is the rule's goal, not built yet",
     ("Yes, as an app", "Yes, inside the kernel cell", "Yes, but only for websites"),
     "The only block today is an app's empty network namespace."),
    ("An app without the network permission connects somewhere. Result?", "Blocked by its empty network namespace",
     ("Allowed on port 443", "Blocked by a firewall rule", "Allowed but logged"),
     "No permission, no network at all, for any host or port."),
    ("Are connections made by the OS itself blocked and logged today?", "No, only apps are covered",
     ("Yes, all of them", "Yes, but not logged", "Only inbound ones"),
     "README gap: nothing yet blocks or logs connections made by the OS or from outside the sandbox."),
    ("By rule 3, what happens to a plain http:// connection?", "It is refused, never silently upgraded",
     ("It is upgraded to https", "It is allowed once", "It is allowed on local networks"),
     "That is the rule; since no firewall exists yet, it is not enforced for everything."),
    ("An app with the network permission can reach:", "Every host and port, and listen for incoming connections",
     ("Only hosts you listed", "Only the host in its manifest", "Only HTTPS sites"),
     "The permission is one yes or no. Rules naming one app, host and port are still to be built."),
)

DEVICES = (
    ("How do you let an app receive mouse clicks?", "Answer y to Boot mouse? and type the password",
     ("Plug the mouse in", "Give the app a permit", "Nothing, it is on by default"),
     "Booting a device is the action device.mouse. The OS reads the mouse and sends commands."),
    ("Which key combination can an app never trap?", "Ctrl-C",
     ("Ctrl-Q", "Esc", "Enter"),
     "Ctrl-C is reserved by the OS in every mode."),
    ("What opens the App Library in the desktop?", "The right mouse button",
     ("The left mouse button", "Ctrl-N", "Ctrl-Q"),
     "In the desktop the OS takes the right button; the app never sees it."),
    ("What does the app receive when you click?", "A pointer or button command",
     ("A raw mouse device", "A file descriptor for /dev/input", "Nothing"),
     "The OS turns the click into commands; apps never touch devices."),
    ("After run graphical hello, do keys reach the app straight away?", "No, you answer y to Boot keyboard? and type the password",
     ("Yes, always", "Yes, after the permit", "Only after Ctrl-C"),
     "device.keyboard is its own password-protected action."),
    ("In the suite apps, which key quits and which backs out?", "Ctrl-Q quits, Esc backs out",
     ("Ctrl-C quits, Enter backs out", "Esc quits, Ctrl-Q backs out", "Ctrl-N quits"),
     "Ctrl-N opens the built-in agent in every suite app."),
)

CELLS = (
    ("What is a cell?", "A separate Linux kernel in a KVM micro-VM on its own CPU cores",
     ("A folder an app owns", "A sandboxed app", "A kind of password"),
     "Cells run in parallel, each pinned to its own cores."),
    ("Which command runs hello inside the cell c1?", "run hello --cell c1",
     ("kos cell hello c1", "kos open hello c1", "run hello --vm c1"),
     "The app uses the same command protocol, carried over vsock."),
    ("Starting a cell needs the password. Which action is it?", "cell.start",
     ("app.remove", "admin.boot", "disk.optimize"),
     "Stopping one is cell.stop."),
    ("Can an app call the kernel or hardware directly?", "No, only the OS does",
     ("Yes, with a permit", "Yes, from inside a cell", "Yes, if it is graphical"),
     "Apps only talk to the OS through commands."),
    ("Which command checks which kernel protections this machine has?", "kos doctor",
     ("kos cell", "kos firmware", "kos usb"),
     "kos doctor has no password because it must run before one exists."),
    ("Unlocking requires the administrator keyboard. What does that require?", "The kernel protections",
     ("A second password", "A cell", "A network connection"),
     "If the kernel protections are missing, the computer simply does not unlock."),
)

COMMANDS = (
    ("Choose your password for the first time.", "kos setup", ("kos passwd", "kos install", "kos doctor"),
     "kos passwd changes it later."),
    ("Change your password.", "kos passwd", ("kos setup", "kos permit", "kos admin"),
     "It needs the action auth.change."),
    ("Stop an app that was opened in the background.", "kos close", ("kos remove", "kos ps", "kos attach"),
     "kos attach only connects your terminal; Ctrl-C there detaches without killing it."),
    ("List the apps opened in the background.", "kos ps", ("kos list", "kos activity", "kos close"),
     "kos list shows installed apps."),
    ("Check the log of password decisions for tampering.", "kos audit --verify", ("kos security", "kos activity", "kos owed"),
     "Plain kos audit just lists the decisions."),
    ("Scan a file right now.", "kos scan file PATH", ("kos view PATH", "kos cat PATH", "kos explore"),
     "It needs no password; kos scan watch DIR needs one to start."),
    ("Open kos://web/example.com like an address bar.", "kos go", ("kos open", "kos attach", "kos explore"),
     "run and open take addresses too."),
    ("Reclaim disk space by recompressing installed apps.", "kos optimize", ("kos settle", "kos remove", "kos backup"),
     "One password covers it."),
    ("Back up a folder, stored once per content.", "kos backup add", ("kos write", "kos optimize", "kos convert"),
     "Files are scanned before they are stored."),
    ("See management processors such as Intel ME or AMD PSP.", "kos firmware", ("kos doctor", "kos usb", "kos aios"),
     "It also says whether the OS would boot."),
)

# (job, app title, one-line why). The wrong choices are other apps from this list.
SAFARI = (
    ("Write a letter or a report", "Document Editor", "Documents live here."),
    ("Add up a column with a formula", "Spreadsheet Editor", "Formulas and tables."),
    ("Build slides for a talk", "Presentation Editor", "Slides."),
    ("Book a meeting at a time", "Calendar Manager", "It owns the calendar folder."),
    ("Keep names, emails and phone numbers", "Contact Manager", "It owns the contacts folder."),
    ("Track to-dos with a due date", "Task Manager", "It owns the tasks folder."),
    ("Jot down notes", "Note-Taking Tool", "Plain notes."),
    ("Draw a flowchart", "Diagram Editor", "Boxes and arrows."),
    ("Collect answers from people", "Survey Builder", "Questions plus results."),
    ("Make a test with right answers", "Quiz Creator", "Marks the right option."),
    ("Log how long work took", "Time Tracking Tool", "Hours per task."),
    ("Make a small web page", "Website Builder", "Sites are apps too and follow the same rules."),
    ("Read the hash-chained log of changes", "Audit Log Manager", "The suite's own audit log."),
    ("Learn facts with cards", "Flashcards", "Front and back."),
    ("Track spending against a budget", "Budget Tracker", "Money in and out."),
    ("Play a board game", "Chess", "A game, offline."),
    ("Keep a daily diary", "Journal", "One entry a day."),
    ("Build a daily streak of habits", "Habit Tracker", "Streaks."),
    ("Save places with a category", "Places", "It owns the places folder."),
    ("Read help about KOS itself", "KOS Help", "Help built into the suite."),
)


def _safari() -> tuple:
    names, n, out = [a for _, a, _ in SAFARI], len(SAFARI), []
    for i, (job, right, why) in enumerate(SAFARI):
        wrong = tuple(names[(i + k) % n] for k in (7, 11, 17))
        out.append((f"Which app: {job}?", right, wrong, why))
    return tuple(out)


PARTS = (
    ("pipeline", "The Pipeline", "screen, app, OS, kernel, hardware", PIPELINE),
    ("password", "Password Everywhere", "which actions need your password", PASSWORD),
    ("sandbox", "Apps and the Sandbox", "what a sandboxed app can and cannot do", SANDBOX),
    ("permits", "Permits and Permissions", "permit vs password vs manifest", PERMITS),
    ("shared", "Shared Folders", "owner, user and grant", SHARED),
    ("blocked", "Blocked by Default", "connections, honestly", BLOCKED),
    ("devices", "Keyboard and Mouse", "booting devices, Ctrl-C, right-click", DEVICES),
    ("cells", "Cells and the Kernel", "micro-VMs and the kernel", CELLS),
    ("commands", "Name That Command", "match the job to the kos command", COMMANDS),
    ("safari", "Suite Safari", "which app does this job", _safari()),
)
KEYS = [p[0] for p in PARTS]


class Game(Screen):
    """One generic quiz over one part: ask, show the explanation, next; saves completion when finished."""

    def __init__(self, hub, part, plays: int):
        self.hub, self.part, self.title = hub, part, part[1]
        rng = random.Random(f"{hub.seed}:{part[0]}:{plays}")
        self.qs = []
        for text, right, wrong, why in rng.sample(list(part[3]), len(part[3])):
            ch = rng.sample([right, *wrong], 1 + len(wrong))
            self.qs.append((text, ch, ch.index(right), why))
        self.i = self.score = self.streak = self.best = self.sel = 0
        self.shown = False
        self.help = "up/down or 1-4 choose   Enter answer   Esc back"

    def render(self, w, h):
        n = len(self.qs)
        if self.i >= n:
            return ["", f"  Finished: {self.score}/{n} right, best streak {self.best}.", "", "  Esc to go back"]
        text, ch, ok, why = self.qs[self.i]
        out = [f" Question {self.i + 1}/{n}   score {self.score}   streak {self.streak}", ""]
        out += [" " + x for x in wrap(text, w - 3)] + [""]
        for j, c in enumerate(ch):
            mark = ("RIGHT " if j == ok else "wrong ") if self.shown and (j == ok or j == self.sel) else ""
            out += wrap(f"{'>' if j == self.sel else ' '} {j + 1}. {mark}{c}", w - 3)
        if self.shown:
            out += [""] + [" " + x for x in wrap(why, w - 3)] + ["", " Enter for next"]
        return out

    def key(self, k):
        if k == "escape": return ("pop", None)
        if self.i >= len(self.qs): return None
        n = len(self.qs[self.i][1])
        if not self.shown:
            if k == "up": self.sel = max(0, self.sel - 1)
            elif k == "down": self.sel = min(n - 1, self.sel + 1)
            elif len(k) == 1 and k.isdigit() and 1 <= int(k) <= n: self.sel = int(k) - 1
            elif k == "enter":
                self.shown = True
                if self.sel == self.qs[self.i][2]: self.score += 1; self.streak += 1; self.best = max(self.best, self.streak)
                else: self.streak = 0
        elif k == "enter":
            self.i += 1; self.sel = 0; self.shown = False
            if self.i >= len(self.qs): self.hub.finish(self.part[0], self.score, len(self.qs), self.best)


class Hub(Screen):
    title = "Get to Know KOS"

    def __init__(self, host, seed: int = 1):
        self.st, self.seed, self.nav = Store(host), seed, ListNav(len(PARTS) + 1)
        self.help = "up/down or 1-9   Enter play   Esc quit"
        d = self.st.load("tour", {})
        d = d if isinstance(d, dict) else {}
        self.done = {k: v for k, v in (d.get("done") or {}).items() if k in KEYS and isinstance(v, list) and len(v) == 3} if isinstance(d.get("done"), dict) else {}
        self.plays = d.get("plays") if isinstance(d.get("plays"), int) else 0

    def finish(self, key, score, total, best):
        old = self.done.get(key)
        if not old or not all(isinstance(x, int) for x in old) or score >= old[0]:
            self.done[key] = [score, total, best]
        self.st.save("tour", {"done": self.done, "plays": self.plays})

    def render(self, w, h):
        out = [f" Parts explored {len(self.done)}/{len(PARTS)}", ""]
        for i, (key, name, blurb, qs) in enumerate(PARTS):
            d = self.done.get(key)
            out.append(f"{'>' if i == self.nav.sel else ' '} {i + 1:>2}. {name:<24} {f'{d[0]}/{d[1]}' if d else '-':>5}  {blurb}"[:w])
        out.append(f"{'>' if self.nav.sel == len(PARTS) else ' '}     Explored: what you have finished")
        return out

    def key(self, k):
        if self.nav.key(k): return None
        i = self.nav.sel
        if k.isdigit() and k != "0": i = int(k) - 1 if int(k) <= len(PARTS) else i
        elif k != "enter": return ("quit",) if k == "escape" else None
        if i == len(PARTS) or k == "0":
            from .ui import TextView
            lines = [f"Parts explored {len(self.done)}/{len(PARTS)}", ""] + [
                f"{'done' if p[0] in self.done else 'not yet':<8}{p[1]}" for p in PARTS]
            return ("push", TextView("Explored", lines))
        if 0 <= i < len(PARTS):
            self.plays += 1
            return ("push", Game(self, PARTS[i], self.plays))


def make(host, entry):
    return Hub(host)


ENTRIES: list = [app(
    "Get to Know KOS", make, "full",
    "A guide to KOS as it is today: ten short quiz games, one per part of the OS, each with a one-line explanation. "
    "It lists nothing that is not built, and says plainly where something (a firewall, encryption) is not done yet.")]
