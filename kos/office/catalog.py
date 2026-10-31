"""The catalogue: every product that was asked for, what engine runs it, and
an honest scope. `scope`:
  full     does the job it is named for, as a single-user local app
  partial  does a real, useful part of it (the note says which part and what is missing)
  none     not built, and why

Every app is single-user and local: KOS apps cannot talk to other apps, other
machines or the network unless the owner grants network access at launch."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field

from . import extras
from .board import Board
from .builder import AppBuilder, BotConsole, SiteBuilder
from .calendar_ import CalendarView, SlotScheduler
from .diagram import SAMPLE as DIAGRAM_SAMPLE, diagram_editor
from .docs import Library, NoteBook, DocEditor, SLIDE_TEMPLATE, slide_editor, md_html
from .flow import FlowApp
from .mail import MailAdmin, MailClient
from .pixels import ImageEditor, ImageGenerator
from .quiz import QuizApp
from .records import Data, RecordList
from .security import AuditLog, AuthSystem, RbacApp
from .sheet import Sheet, SheetEditor
from .specs import S
from .sqlapp import SqlConsole
from .ui import Editor, Menu, Screen
from .workbench import Chat, ModelSettings, TOOLS, Workbench
from . import tools


@dataclass
class Entry:
    title: str
    kind: str
    scope: str = "full"
    note: str = ""
    name: str = ""
    args: dict = field(default_factory=dict)
    network: bool = False
    graphical: bool = False

    def __post_init__(self):
        if not self.name:
            self.name = re.sub(r"[^a-z0-9]+", "-", self.title.lower()).strip("-")


# --------------------------------------------------------------- builders ----
def _docs(host, e):
    a = e.args
    lib = Library(host, e.title, a.get("noun", "document"), lambda n, t, s: _doc_editor(host, e, n, t, s), a.get("template", "# Untitled\n\n"))
    return lib


def _doc_editor(host, e, n, t, s):
    a = e.args
    ed = DocEditor(host, n, t, s, assist=a.get("assist"))
    if a.get("layout"):
        def layout(ed_):
            html = md_html(ed_.area.text, n).replace("<body>", "<style>@page{size:A4;margin:18mm}body{columns:2;column-gap:8mm;font:11pt/1.4 Georgia,serif}h1,h2{column-span:all}p{text-align:justify;orphans:3;widows:3}</style><body>", 1)
            host.put(f"export-{n.lower().replace(' ', '-')}-layout.html", html); ed_.flash = "wrote two-column print layout (HTML, A4) to the vault"
        ed.extra["ctrl-l"] = layout; ed.hint += "  ^L print layout"
    return ed


def _sheet_opener(host):
    def op(name, text, save):
        try: cells = json.loads(text) if text.strip().startswith("{") else {}
        except ValueError: cells = {}
        return SheetEditor(name, Sheet(cells), lambda sh: save(json.dumps(sh.cells)))
    return op


def _sheets(host, e): return Library(host, e.title, "spreadsheet", _sheet_opener(host), "{}", "sheet-")
def _slides(host, e): return Library(host, e.title, "deck", lambda n, t, s: slide_editor(host, n, t, s), e.args.get("template", SLIDE_TEMPLATE), "deck-")
def _diagram(host, e): return Library(host, e.title, "diagram", lambda n, t, s: diagram_editor(host, n, t, s), DIAGRAM_SAMPLE, "dia-")
def _records(host, e): r = RecordList(Data(host, S[e.args["spec"]])); r.title = e.title; return r
def _wb(host, e): return Workbench(host, e.title, e.args["tools"], e.args.get("intro", ""))
def _search(host, e): return extras.SearchLibrary(host, e.title, e.args.get("noun", "document"), ask=e.args.get("ask", False), hold=e.args.get("hold", False))

SYSTEMS = {
    "assistant": "You are a concise, accurate assistant. If you are unsure, say so.",
    "writing": "You are a careful writing assistant. Improve clarity and concision; keep the author's voice; explain significant changes briefly.",
    "research": "You are a research assistant. Separate what is established from what is uncertain, and say what you would check next.",
    "coding": "You are a senior software engineer. Prefer simple, correct code; point out bugs, edge cases and security issues.",
    "meeting": "You turn meeting notes into decisions, action items with owners, and open questions.",
    "email": "You draft clear, polite, appropriately short emails and replies. Offer a subject line.",
    "document": "You answer questions about documents using only what they say, and quote the relevant passage.",
    "spreadsheet": "You help with spreadsheet formulas and data analysis. Give the exact formula and one line on how it works.",
    "presentation": "You turn ideas into tight slide outlines: one idea per slide, at most five bullets.",
    "data": "You are a data analyst. State assumptions, give the method, and flag small samples and outliers.",
    "content": "You are a content creator. Match the requested tone and audience; give a draft, then two alternatives for the opening.",
}


def _assistant(host, e):
    a = e.args; parts = []
    sysmsg = SYSTEMS[a.get("system", "assistant")]
    if a.get("docs"): parts.append(("Documents", lambda h: Library(h, "Documents", "document", lambda n, t, s: DocEditor(h, n, t, s, assist=tools.writing_check if a["docs"] == "writing" else None), "# Untitled\n\n")))
    if a.get("notes"): parts.append(("Notes", lambda h: NoteBook(h)))
    if a.get("sheets"): parts.append(("Spreadsheets", lambda h: Library(h, "Spreadsheets", "spreadsheet", _sheet_opener(h), "{}", "sheet-")))
    if a.get("slides"): parts.append(("Slide decks", lambda h: Library(h, "Decks", "deck", lambda n, t, s: slide_editor(h, n, t, s), SLIDE_TEMPLATE, "deck-")))
    if a.get("search"): parts.append(("Search my documents", lambda h: extras.SearchLibrary(h, "Search", "document", ask=True)))
    if a.get("tools"): parts.append(("Tools (work without a model)", lambda h: Workbench(h, "Tools", a["tools"])))
    parts.append(("Chat" + (" - connect a model for full answers" if True else ""), lambda h: Chat(h, e.title, sysmsg)))
    parts.append(("Model settings", lambda h: ModelSettings(h)))
    return extras.Hub(host, e.title, parts, "Works offline with local tools; connect a language model in Model settings (needs network permission) for open-ended answers.", prefixed=False)


def _persona(host, e):
    def chat(h):
        persona = h.get("persona") or "You are a helpful assistant."
        from .search import Index
        def know(text, hits):
            ix = Index({n: h.get(v["key"]) or "" for n, v in (__import__("json").loads(h.get("index") or "{}")).items()})
            res = ix.search(text, 3)
            return ("From my knowledge:\n" + "\n".join(f"[{n}] {s}" for n, _x, s in res)) if res else None
        return Chat(h, e.title, persona, extra_local=know)
    parts = [("Edit persona (system prompt)", lambda h: Editor("Persona", h.get("persona") or "You are a friendly support assistant for Acme.\nAnswer briefly. If you do not know, say so.\n", on_save=lambda t: h.put("persona", t))),
             ("Knowledge (documents the assistant can search)", lambda h: Library(h, "Knowledge", "document", lambda n, t, s: Editor(n, t, s), "", "doc-")),
             ("Talk to it", chat), ("Model settings", lambda h: ModelSettings(h))]
    return extras.Hub(host, e.title, parts, "Define a persona and a knowledge base, then talk to the result.", prefixed=False)


def _hub(host, e):
    parts = []
    for label, kind, arg in e.args["parts"]:
        if kind == "records": parts.append((label, lambda h, s=arg: RecordList(Data(h, S[s]))))
        elif kind == "wb": parts.append((label, lambda h, t=arg: Workbench(h, label, t)))
        elif kind == "sql": parts.append((label, lambda h: SqlConsole(h, label)))
        elif kind == "notes": parts.append((label, lambda h: NoteBook(h)))
        elif kind == "quiz": parts.append((label, lambda h: QuizApp(h, label, "quiz")))
        elif kind == "rbac": parts.append((label, lambda h: RbacApp(h, label)))
        elif kind == "flow": parts.append((label, lambda h: FlowApp(h, label, "builder")))
        elif kind == "api": parts.append((label, lambda h: extras.ApiTool(h, label)))
        elif kind == "builder": parts.append((label, lambda h: AppBuilder(h, label)))
        elif kind == "tasks": parts.append((label, lambda h: RecordList(Data(h, S["tasks"]))))
        elif kind == "calendar": parts.append((label, lambda h: CalendarView(h, label)))
        elif kind == "channels": parts.append((label, lambda h: extras.Channels(h, label)))
        elif kind == "docs": parts.append((label, lambda h: Library(h, label, "document", lambda n, t, s: DocEditor(h, n, t, s), "# Untitled\n\n")))
    return extras.Hub(host, e.title, parts, e.args.get("intro", ""))


BUILD = {
    "docs": _docs, "sheets": _sheets, "slides": _slides, "diagram": _diagram, "records": _records, "wb": _wb, "search": _search,
    "notes": lambda h, e: NoteBook(h, e.title, e.args.get("noun", "note")), "sql": lambda h, e: SqlConsole(h, e.title),
    "calendar": lambda h, e: CalendarView(h, e.title), "scheduler": lambda h, e: SlotScheduler(h, e.title),
    "board": lambda h, e: Board(h, e.title, e.args.get("snap", 1)), "pixels": lambda h, e: ImageEditor(h, e.title), "imagegen": lambda h, e: ImageGenerator(h, e.title),
    "mail": lambda h, e: MailClient(h, e.title), "mailadmin": lambda h, e: MailAdmin(h, e.title),
    "quiz": lambda h, e: QuizApp(h, e.title, "quiz"), "survey": lambda h, e: QuizApp(h, e.title, "survey"),
    "builder": lambda h, e: AppBuilder(h, e.title, guided=e.args.get("guided", False)),
    "site": lambda h, e: SiteBuilder(h, e.title, e.args.get("site", "website")), "bot": lambda h, e: BotConsole(h, e.title, e.args.get("slots", True)),
    "flow": lambda h, e: FlowApp(h, e.title, e.args.get("role", "builder"), e.args.get("sample", ""), e.args.get("input", "")),
    "assistant": _assistant, "persona": _persona, "hub": _hub, "dashboard": lambda h, e: extras.Dashboard(h, e.title),
    "auth": lambda h, e: AuthSystem(h, e.title), "rbac": lambda h, e: RbacApp(h, e.title), "audit": lambda h, e: AuditLog(h, e.title),
    "api": lambda h, e: extras.ApiTool(h, e.title), "script": lambda h, e: Library(h, e.title, "script", lambda n, t, s: extras.script_editor(h, n, t, s), "", "scr-"),
    "channels": lambda h, e: extras.Channels(h, e.title),
}


def build(host, e: Entry) -> Screen: return BUILD[e.kind](host, e)


# ---------------------------------------------------------------- catalogue ----
def E(title, kind, scope="full", note="", **args):
    net = args.pop("network", False); gfx = args.pop("graphical", False); name = args.pop("name", "")
    return Entry(title, kind, scope, note, name, args, net, gfx)


def R_(title, spec, scope="full", note="", **kw): return E(title, "records", scope, note or S[spec].scope, spec=spec, **kw)


SAMPLE_MERGE_DOC = "flow Letters\nenabled: yes\ngoal: one letter per row\nstep: input\nstep: template Dear {name}, thank you for your {item} order of ${total}. Regards, Ops\nstep: save letters\n"
SAMPLE_MERGE_MAIL = "flow Reminder drafts\nenabled: yes\ngoal: one reminder email body per overdue row\nstep: input\nstep: pipeline filter days_late>0\nstep: template To: {email}\\nSubject: Invoice {invoice} is {days_late} days late\\n\\nHi {name}, ...\nstep: save reminders\n"
SAMPLE_FORM = "flow Route submissions\nenabled: yes\ngoal: tag each submission by its amount\nstep: input\nstep: pipeline addcol route = IF(amount>1000,\"finance\",\"auto-approve\") | sort amount desc\nstep: save routed\n"
SAMPLE_SHEET_AUTO = "flow Monthly cleanup\nenabled: yes\ngoal: drop empties, add a total, sort\nstep: input\nstep: pipeline dedupe | addcol total = qty*price | sort total desc\nstep: save cleaned\n"
SAMPLE_AI_FLOW = "flow Brief the team\nenabled: yes\ngoal: turn a long update into a short email (needs a model for the last step)\nstep: input\nstep: summarize 3\nstep: ask Rewrite as a friendly two-paragraph email to the team\nstep: save brief\n"
MERGE_INPUT = "name,item,total,email,invoice,days_late\nAnn,Widget,25,ann@x.io,INV-1,3\nBob,Gadget,40,bob@x.io,INV-2,0\n"
FORM_INPUT = "name,amount\nAnn,250\nBob,5200\nCy,980\n"
SHEET_INPUT = "item,qty,price\na,2,3\nb,5,4\na,2,3\nc,1,9\n"

CATALOG: list[Entry] = [
 E("Document Editor", "docs"), E("Spreadsheet Editor", "sheets"), E("Presentation Editor", "slides"),
 E("Note-Taking Tool", "notes"), E("Database Manager", "sql"),
 E("Desktop Publishing Tool", "docs", "partial", "Writes Markdown and exports a two-column A4 print layout as HTML (Ctrl-L). No WYSIWYG page designer, fonts or images.", layout=True, template="# Headline\n\nBody text flows into two justified columns when exported.\n"),
 E("Diagram Editor", "diagram", note="Text-defined flow diagrams drawn as boxes and arrows; SVG export."),
 E("Interactive Presentation Builder", "slides", template="# Quick poll\n---\n## Which option?\n? Pick one | Option A | Option B | Option C\n[See the answer](#3)\n---\n# Thanks\n> poll votes are saved; press a/b/c while presenting\n", note="Slides with live polls (votes counted on this device) and branching links."),
 E("Email Client", "mail", "partial", "Local accounts, folders, compose/reply/forward, search, rules and a relay queue. SMTP/IMAP to other servers only via an optional relay with network access; it does not fetch mail from other providers.", network=True),
 E("Email Server", "mailadmin", "partial", "The mail system without sockets: mailboxes, aliases, routing rules, quotas, bounces, relay queue, mbox export. It does not listen on SMTP/IMAP ports (KOS apps cannot), and does not exchange mail with the Email Client app.", network=True),
 E("Calendar Manager", "calendar"), R_("Contact Manager", "contacts"),
 E("Appointment Scheduler", "scheduler", note="Working hours, slot length, free-slot list, booking with double-booking prevention. No public booking page."),
 R_("Workplace Planner", "workplace"), R_("Team Management Tool", "team"),
 E("Cloud Storage", "docs", "partial", "A local text-object store (create, edit, copy, search, export). There is no cloud: no remote storage, accounts or sync.", noun="object", template=""),
 E("File Synchronization Tool", "wb", "partial", "Computes the sync plan (copy/update/delete/conflict, three-way with a base listing) from pasted file listings. It cannot read or move files itself.", tools=["sync"]),
 R_("Document Management System", "docmgmt", "partial", "A document register with versions, owners, approval status and review dates; documents themselves are not stored."),
 E("Content Management System", "site", site="cms", note="Markdown entries with draft/published status; build writes only published ones as a linked static site."),
 E("Intranet Builder", "site", site="intranet"),
 R_("Task Manager", "tasks"), R_("Project Planner", "planner"), R_("Project Management System", "projects"),
 E("Team Collaboration Tool", "hub", "partial", "Tasks, notes, calendar and channels in one place. Single device: no shared real-time editing with other people.", parts=[("Tasks", "tasks", None), ("Channels", "channels", None), ("Notes", "notes", None), ("Calendar", "calendar", None)]),
 E("Messaging Platform", "channels", "partial", "Local channels with @mentions, search, pins. Messages stay on this device: no delivery to other people."),
 R_("Video Conferencing Tool", "meetings", "partial"),
 E("Voice Calling System", "none", "none", "Needs real-time audio and a network stack; the KOS command protocol carries text and pixels only."),
 R_("Webinar Platform", "webinars", "partial"), R_("Virtual Meeting Room System", "rooms", "partial"),
 E("Collaborative Whiteboard", "board", "partial", "Pen, line, rectangle, box, text, eraser, undo, SVG export (graphical mode, mouse). One person at a time: no live sharing.", graphical=True),
 E("Collaborative Workspace", "hub", "partial", "Notes, tasks, documents and a calendar in one workspace. Single device; no live co-editing.", parts=[("Notes", "notes", None), ("Tasks", "tasks", None), ("Documents", "docs", None), ("Calendar", "calendar", None)]),
 E("Online Form Builder", "builder", guided=True, note="Define fields, then fill in the form and review/export responses. Forms are not published to a web address."),
 E("Survey Builder", "survey"), E("Quiz Creator", "quiz"),
 E("Website Builder", "site", site="website", note="Markdown pages to a linked static site (HTML written to the vault). It does not host it."),
 E("Portal Builder", "site", site="portal", note="A landing page of cards linking to resources, built as static HTML. No logins."),
 R_("Video Editor", "edl", "partial"),
 E("Image Editor", "pixels", "partial", "A 24x24 pixel-art editor: paint, fill, flip, rotate, invert, grayscale, undo, export PPM/SVG/PNG. Not a photo editor.", graphical=True),
 E("Image Generator", "imagegen", "partial", "Procedural images (gradients, plasma, Mandelbrot, spirals…) with seeds and palettes, exported as PPM/SVG/PNG. Not a text-to-image AI model.", graphical=True),
 E("Graphic Design Tool", "board", "partial", "Shape and text layout on a snap grid with SVG export (graphical mode). No fonts, images or layers.", graphical=True, snap=10),
 E("Screen Capture Tool", "none", "none", "KOS apps cannot read the screen or other apps by design; a capture tool would break the security model."),
 E("Document Scanner", "none", "none", "Needs a camera/scanner device and image recognition; apps get no such device."),
 R_("Video Hosting Platform", "videos", "partial"), R_("Photo Manager", "photos", "partial"),
 E("AI Assistant", "assistant", "partial", "Chat with local tools offline; a connected language model gives open-ended answers.", system="assistant", tools=["summarize", "extract", "writing", "analyze"], network=True),
 E("AI Writing Assistant", "assistant", "partial", "Offline: readability, passive voice, filler, long sentences, summaries. Rewrites need a connected model.", system="writing", docs="writing", tools=["writing", "summarize", "translate"], network=True),
 E("AI Research Assistant", "assistant", "partial", system="research", notes=True, tools=["summarize", "extract", "writing"], network=True, note="Notes with links and ranked search; summaries are extractive. Open-ended research needs a connected model (it cannot browse by itself)."),
 E("AI Coding Assistant", "assistant", "partial", "Offline: syntax check, complexity, unused imports, TODOs. Code generation/explanation needs a connected model. It does not run code.", system="coding", tools=["code"], network=True),
 E("AI Meeting Assistant", "assistant", "partial", "Offline: pulls action items, decisions and questions out of notes; transcript→SRT. It does not listen to meetings.", system="meeting", tools=["meeting", "summarize", "srt"], network=True),
 E("AI Email Assistant", "assistant", "partial", "Offline: writing checks and summaries. Drafting replies needs a connected model.", system="email", tools=["writing", "summarize", "extract"], network=True),
 E("AI Document Assistant", "assistant", "partial", "Offline: ranked search and extractive summaries; question answering needs a connected model.", system="document", search=True, tools=["summarize", "extract", "writing"], network=True),
 E("AI Spreadsheet Assistant", "assistant", "partial", "Offline: describe a calculation, get the formula; column statistics and charts. Open-ended analysis needs a model.", system="spreadsheet", sheets=True, tools=["formula", "analyze", "chart", "transform"], network=True),
 E("AI Presentation Assistant", "assistant", "partial", "Offline: turns an indented outline into slides. Writing content needs a connected model.", system="presentation", slides=True, tools=["outline", "summarize"], network=True),
 E("AI Search Assistant", "search", "partial", "Ranked (BM25) search over documents you add; answers need a connected model.", ask=True, network=True),
 E("AI Agent Builder", "flow", "partial", "Agents are deterministic step pipelines (summarize, extract, redact, tables, recall, ask-a-model, save). Not autonomous: they run when you run them.", network=True, sample=SAMPLE_AI_FLOW),
 E("AI Agent Manager", "flow", "partial", "Registry of agents: enable/disable, run, run-all-enabled, history. No background scheduling: KOS has no background services, by design.", role="manager", network=True),
 E("Workflow Automation Tool", "flow", note="Step pipelines over text and tables, run on demand."),
 R_("Business Process Automation Tool", "processes", "partial", "Approval workflows with SLA tracking: move each request through its steps. No integrations that act in other systems."),
 E("Application Builder", "builder", note="Define tables in a small schema language and use them immediately as record apps."),
 E("Low-Code Development Platform", "builder", note="Schema language with calculated fields using spreadsheet formulas (e.g. total = qty * price)."),
 E("No-Code Development Platform", "builder", guided=True, note="Add fields one prompt at a time; no syntax to learn."),
 E("Script Editor", "script", note="Python editor with run (time-limited, import allowlist) and a syntax/complexity check."),
 E("Macro Recorder", "flow", role="recorder", note="Record text/table steps with a live preview, save as a replayable macro. Records steps typed here, not keystrokes in other apps."),
 E("API Integration Tool", "api", "partial", "Build, send and inspect HTTP requests; pick fields from JSON; generate curl/Python. It does not run integrations on a schedule.", network=True),
 E("Application Integration Platform", "hub", "partial", "Request builder plus flows. No hosted connectors or scheduler.", network=True, parts=[("API requests", "api", None), ("Flows", "flow", None), ("Integration register", "records", "integrations")]),
 E("Data Import Tool", "wb", tools=["import"]), E("Data Transformation Tool", "wb", tools=["transform", "import"]),
 E("Data Analysis Tool", "wb", tools=["analyze", "chart", "transform", "import"]),
 E("Business Intelligence Platform", "hub", "partial", "SQL console, analysis, charts and dashboards over data you paste in. No live connections to external sources.", parts=[("Dashboard", "wb", ["analyze", "chart"]), ("SQL", "sql", None), ("Import & transform", "wb", ["import", "transform"])]),
 E("Data Visualization Tool", "wb", "partial", "Text charts (bars, histograms, sparklines). No graphical chart types.", tools=["chart", "analyze"]),
 E("Dashboard Builder", "dashboard", "partial", "KPI tiles, bar/histogram/line and table widgets over a pasted table, in text."),
 E("Data Modeling Tool", "wb", tools=["model"], note="Entity DSL to SQL DDL, with checks for missing keys and dangling references."),
 E("Data Warehouse", "sql", "partial", "A SQL database with saved queries run as an ordered pipeline (.runall). In-memory SQLite persisted as a dump: fine for small data, not a warehouse engine."),
 E("Data Engineering Platform", "hub", "partial", "SQL with saved-query pipelines, table transforms, flows. Small data only; no scheduler or connectors.", parts=[("SQL pipelines", "sql", None), ("Transform", "wb", ["import", "transform"]), ("Flows", "flow", None)]),
 E("Relational Database", "sql", "partial", "Real SQL on SQLite, persisted to the vault. Single user; ATTACH is disabled."),
 E("Data Management Platform", "hub", "partial", "Data-asset register plus SQL and import for small datasets. No connectors, lineage or scheduled jobs.", parts=[("Datasets & SQL", "sql", None), ("Import", "wb", ["import"]), ("Data asset register", "records", "governance")], intro="Data inventory plus SQL and import. Small data only."),
 E("Enterprise Search Tool", "search", "partial", "Ranked search over documents you add (BM25). It does not crawl other systems or files."),
 E("File Search Tool", "search", "partial", "Ranked search over text you add. Apps cannot read your files, so it cannot index a disk.", noun="file"),
 E("Knowledge Management System", "notes", note="Notes with tags, [[links]] and backlinks, plus ranked search.", noun="article"),
 E("Knowledge Base", "search", noun="article"), E("Research Notebook", "notes"),
 E("Information Extraction Tool", "wb", tools=["extract"]), E("Text Summarization Tool", "wb", "partial", "Extractive: selects the key sentences; it does not paraphrase.", tools=["summarize"]),
 E("Translation Tool", "wb", "partial", "Phrase-glossary substitution for en→es/fr/de on a small built-in glossary; it is not machine translation and says which words it did not know.", tools=["translate"]),
 E("Speech Recognition Tool", "none", "none", "Needs a microphone and a speech model; apps get no audio device."),
 E("Text-to-Speech Tool", "none", "none", "Needs a speech synthesizer and an audio device; apps get no audio output."),
 E("Transcription Tool", "wb", "partial", "Edits timestamped transcripts and converts to SRT/WebVTT. It does not transcribe audio.", tools=["srt"]),
 R_("Meeting Recording Tool", "recordings", "partial"),
 E("Meeting Summarization Tool", "wb", "partial", "Extractive summary plus action items/decisions/questions found by pattern.", tools=["meeting", "summarize"]),
 R_("Task Assignment Tool", "assignments"), R_("Resource Planning Tool", "resources"), R_("Time Tracking Tool", "time", note="Manual time entries with billable value; no running timer (KOS has no background clock)."),
 R_("Employee Engagement Platform", "engagement", "partial", "Pulse, recognition and feedback register with actions; it does not send surveys to people."),
 E("Learning Management System", "hub", "partial", "Courses, learners and quizzes. Single device; learners do not log in.", parts=[("Courses", "records", "courses"), ("Learners", "records", "learners"), ("Quizzes", "quiz", None)]),
 E("Classroom Management System", "hub", "partial", "Roster, attendance and assignments for one teacher on one device. No student logins or messaging.", parts=[("Students", "records", "students"), ("Attendance", "records", "attendance"), ("Assignments", "records", "homework")]),
 R_("Assignment Management Tool", "homework"), E("Educational Assessment Tool", "quiz", note="Multiple-choice (single/multi-answer), scored, with per-question statistics."),
 R_("Identity Management System", "identities", "partial"),
 E("Authentication System", "auth", "partial", "Credential registry & login simulator: scrypt hashes, password policy, TOTP (RFC 6238), lockout. It does not protect any other app's login."),
 E("Access Control Manager", "rbac", "partial", "Roles, inheritance, deny-overrides; answers 'can X do Y' with the reason. It decides, it does not enforce."),
 R_("User Account Manager", "accounts", "partial", "Account register with status and password-expiry tracking; it does not create operating-system accounts."),
 R_("Device Management System", "devices", "partial"), R_("Application Management System", "apps"),
 E("Security Monitoring System", "hub", "partial", "Log threat rules on pasted logs and an incident tracker. It does not collect logs.", parts=[("Analyse a log", "wb", ["threats", "dlp"]), ("Incidents", "records", "incidents")]),
 E("Threat Detection System", "wb", "partial", "Rule-based detection on pasted logs: brute force, port scans, SQLi/XSS/traversal/command injection, scanner UAs. Heuristic; no live feed.", tools=["threats"]),
 E("Endpoint Protection System", "wb", "partial", "Scans pasted content with the KOS static-scanner rules and the sensitive-data scanner. It cannot see or protect a computer's files or processes.", tools=["scan", "dlp"]),
 E("Data Loss Prevention System", "wb", "partial", "Finds and redacts card numbers (Luhn-checked), IBANs, SSNs, keys, tokens, private keys in text you paste. It does not watch other apps or networks.", tools=["dlp"]),
 R_("Data Governance Platform", "governance", "partial", "A register of data assets with owners, classification and quality scores. It does not scan systems or enforce policy."), R_("Privacy Management System", "privacy", "partial", "A register of processing activities, data-subject requests (deadline-flagged) and breaches. It does not discover personal data or contact anyone."), R_("Compliance Management System", "compliance", "partial", "Control register with status, evidence links, review dates and coverage per framework. It does not collect evidence or audit systems."),
 E("Audit Log Manager", "audit", note="Append-only, hash-chained log; verification pinpoints the first tampered entry."),
 R_("Data Retention Manager", "retention", "partial", "Computes expiry dates and what is due for disposal, with legal-hold exceptions. It does not delete anything."),
 E("Electronic Discovery Tool", "search", "partial", "Ranked search across documents you load, with legal-hold marking and a hold report. It does not collect from mailboxes or systems.", hold=True),
 R_("Backup System", "backups", "partial"), R_("Data Recovery System", "recovery", "partial"), R_("Data Archiving System", "archive", "partial", "Register of archived datasets: location, checksum, retention, verification. It does not move or compress data."),
 E("Data Migration Tool", "wb", "partial", "Profile and transform a table (rename, convert, filter, dedupe) before loading elsewhere. No connectors.", tools=["import", "transform"]),
 R_("Data Region Management Tool", "regions", "partial", "Flags datasets stored outside their allowed regions; it does not move data."),
 R_("Subscription Management Tool", "subscriptions"), R_("License Management Tool", "licenses"),
 E("Organization Administration Console", "hub", "partial", "Accounts, groups and access policy in one console (registers and decisions; no directory enforcement).", name="org-admin-console", parts=[("User accounts", "records", "accounts"), ("Groups", "records", "groups"), ("Access policy", "rbac", None)]),
 E("User Permissions Manager", "rbac", "partial", "Roles, inheritance, deny-overrides; effective-permission and wildcard-access reviews."),
 R_("Group Management Tool", "groups"), R_("Directory Service", "directory", "partial", "A directory of entries with parent/child DNs and search. No LDAP/network service."),
 E("Cloud Application Platform", "hub", "partial", "Build apps from schemas and test APIs. There is no cloud hosting.", network=True, parts=[("Application builder", "builder", None), ("API requests", "api", None)]),
 E("Developer API", "api", "partial", "API request workspace with code snippets for curl/Python. It is not an API provider.", network=True),
 R_("Extension Marketplace", "extensions", "partial"), R_("Application Marketplace", "marketplace", "partial"),
 R_("Plugin Manager", "plugins", "partial", "A plugin register: versions, permissions, enabled state. It does not install plugins."),
 R_("Add-On Manager", "addons", "partial", "An add-on register: versions, permissions, enabled state. It does not install add-ons."),
 R_("Integration Manager", "integrations", "partial", "A register of integrations (systems, status, owner, last sync). It does not run or monitor them."), R_("Shared File Manager", "sharedfiles", "partial"),
 R_("Shared Workspace Manager", "sharedspaces", "partial", "Register of workspaces with members, quota and usage. It does not provision or enforce anything."), R_("Digital Asset Manager", "assets", "partial"),
 E("Content Publishing Tool", "site", site="cms", note="Entries with draft/published status; Build publishes only published ones as static HTML."),
 E("Form Automation Tool", "flow", sample=SAMPLE_FORM, input=FORM_INPUT, note="Routes form submissions (a table) by rules, e.g. by amount."),
 E("Spreadsheet Automation Tool", "flow", sample=SAMPLE_SHEET_AUTO, input=SHEET_INPUT, note="Repeatable table clean-up pipelines (dedupe, computed columns, sort)."),
 E("Document Automation Tool", "flow", sample=SAMPLE_MERGE_DOC, input=MERGE_INPUT, note="Mail-merge: one document per row from a template."),
 E("Email Automation Tool", "flow", "partial", "Generates personalised email text per row. It does not send; paste into the Email Client.", sample=SAMPLE_MERGE_MAIL, input=MERGE_INPUT),
 E("Calendar Automation Tool", "wb", "partial", "Expands recurrence rules ('every weekday 09:00 …') into dated events. It does not write to the Calendar Manager (apps cannot share data).", tools=["recur"]),
 E("Chatbot Builder", "bot", slots=False, note="Intents with patterns and replies, a test console, unhandled-question log."),
 E("Conversational AI Platform", "bot", "partial", "Intent matching with multi-turn slot filling and analytics. Rule-based; not a generative model.", slots=True),
 E("Custom AI Assistant Builder", "persona", "partial", "Persona + searchable knowledge + chat. Offline it answers from your knowledge; a connected model makes it conversational.", network=True),
 E("AI Workflow Builder", "flow", "partial", "Flows with an 'ask the model' step (needs a connected model; skipped otherwise).", network=True, sample=SAMPLE_AI_FLOW),
 E("AI Knowledge Retrieval System", "search", "partial", "BM25 retrieval over documents you add, with model-written answers when connected.", ask=True, network=True),
 E("AI-Powered Data Analysis Tool", "assistant", "partial", "Statistics, outliers, correlations, charts offline; model Q&A about the data when connected.", system="data", tools=["analyze", "chart", "transform", "import"], network=True),
 E("AI-Powered Content Creation Tool", "assistant", "partial", "Offline: outline→slides, writing checks. Drafting needs a connected model.", system="content", docs="writing", tools=["outline", "writing", "summarize"], network=True),
 E("AI-Powered Search Engine", "search", "partial", "BM25 over documents you add; model-written answers when connected.", ask=True, network=True),
 E("AI-Powered Recommendation System", "wb", "partial", "Item-based collaborative filtering over a ratings table you provide. Real algorithm, small data.", tools=["recommend"]),
]

NAME_OVERRIDES: dict = {}
BY_NAME = {e.name: e for e in CATALOG}
