"""Record specs for the tracker/registry/manager products, plus the reports
that give a few of them real logic (conflicts, disposal due, coverage)."""

from __future__ import annotations

import re
import time
from collections import defaultdict

from .records import Field, KINDS, Spec

_F = re.compile(r"^([a-z][a-z0-9_]*)\s*:\s*([a-z]+)(?:\(([^)]*)\))?(\*)?(?:\s*=\s*(.*))?$")


def fields(s: str) -> list:
    out = []
    for part in [p.strip() for p in s.split(";") if p.strip()]:
        if ":" not in part:                       # bare 'name', 'name*' or 'name=default'
            name, eq, dflt = part.partition("=")
            req = name.strip().endswith("*")
            part = f"{name.strip().rstrip('*')}: text{'*' if req else ''}" + (f"={dflt}" if eq else "")
        m = _F.match(part)
        assert m, part
        key, kind, ch, req, default = m.groups()
        assert kind in KINDS, (key, kind)
        out.append(Field(key, key.replace("_", " ").title(), kind, tuple(c.strip() for c in (ch or "").split("|") if c.strip()), (default or "").strip(), bool(req)))
    return out


def R(id, title, item, f, **kw) -> Spec:
    kw["calc"] = tuple(tuple(c.split("=", 1)) if isinstance(c, str) else c for c in kw.get("calc", ()))
    kw["calc"] = tuple((k.strip(), v.strip()) for k, v in kw["calc"])
    return Spec(id, title, item, fields(f), **kw)


def today() -> str: return time.strftime("%Y-%m-%d")


# ------------------------------------------------------------- reports ----
def booking_conflicts(items):
    by = defaultdict(list)
    for r in items:
        if r.get("status") != "cancelled": by[(r.get("resource"), r.get("date"))].append(r)
    out = []
    for (res, d), rs in by.items():
        for i, a in enumerate(rs):
            for b in rs[i + 1:]:
                if a.get("from") and b.get("from") and a["from"] < (b.get("to") or "99:99") and b["from"] < (a.get("to") or "99:99"):
                    out.append(f"CONFLICT {res} on {d}: {a['person']} {a['from']}-{a.get('to', '')} overlaps {b['person']} {b['from']}-{b.get('to', '')}")
    return out or ["no double bookings"]


def workload(items):
    t = defaultdict(lambda: [0, 0.0])
    for r in items:
        if r.get("status") not in ("done", "declined"):
            t[r.get("assignee", "?")][0] += 1
            try: t[r.get("assignee", "?")][1] += float(r.get("workload_h") or 0)
            except ValueError: pass
    return [f"{a:<20} {n:>3} open task(s)  {h:>6.1f} h" for a, (n, h) in sorted(t.items(), key=lambda x: -x[1][1])] or ["nothing assigned"]


def utilization(items):
    t = defaultdict(float)
    for r in items:
        try: t[(r.get("person"), r.get("week"))] += float(r.get("hours") or 0)
        except ValueError: pass
    return [f"{p:<18} week of {w}  {h:>5.1f} h  " + ("OVER-ALLOCATED (>40h)" if h > 40 else "under 50%" if h < 20 else "ok") for (p, w), h in sorted(t.items(), key=lambda x: (str(x[0][0]), str(x[0][1])))] or ["no allocations"]


def disposal_due(items):
    out = [f"{r['dataset']}: expired {r['expires']}" for r in items if r.get("expires") and r["expires"] < today() and r.get("legal_hold") != "yes"]
    held = [f"{r['dataset']}: HOLD (would have expired {r.get('expires')})" for r in items if r.get("expires") and r["expires"] < today() and r.get("legal_hold") == "yes"]
    return (["DISPOSE (past retention, no hold):"] + (out or ["  none"]) + ["", "RETAINED BY LEGAL HOLD:"] + (held or ["  none"]))


def coverage(items):
    by = defaultdict(lambda: [0, 0])
    for r in items:
        by[r.get("framework", "?")][1] += 1
        if r.get("status") in ("implemented", "verified"): by[r.get("framework", "?")][0] += 1
    return [f"{f:<10} {d}/{n} controls implemented ({100 * d // n}%)" for f, (d, n) in sorted(by.items())] or ["no controls"]


def backup_health(items):
    out = []
    for r in items:
        why = []
        if r.get("last_result") in ("failed", "never"): why.append(f"last result: {r.get('last_result')}")
        if r.get("verified") != "yes": why.append("restore never verified")
        if why: out.append(f"{r['job']}: " + "; ".join(why))
    return out or ["all jobs succeeded and were verified"]


def portfolio(items):
    out = []
    for r in items:
        try: b, s = float(r.get("budget") or 0), float(r.get("spent") or 0)
        except ValueError: continue
        flag = "OVER BUDGET" if s > b > 0 else ("high risk" if r.get("risk") == "high" else "")
        out.append(f"{r['name'][:24]:<24} {s:>10,.0f} / {b:>10,.0f}  {100 * s / b if b else 0:>5.0f}%  {flag}")
    return out or ["no projects"]


def license_risk(items):
    out = []
    for r in items:
        try: used, seats = float(r.get("used") or 0), float(r.get("seats") or 0)
        except ValueError: continue
        if used > seats: out.append(f"{r['product']}: OVER-USED {used:g}/{seats:g} seats (compliance exposure)")
        elif seats and used / seats < 0.5: out.append(f"{r['product']}: only {100 * used / seats:.0f}% used - consider reducing seats")
    return out or ["no licence problems"]


def region_violations(items):
    return [f"{r['dataset']}: stored in {r.get('stored_region')} but allowed only in {r.get('allowed_regions')}" for r in items if r.get("compliant") == "VIOLATION"] or ["no residency violations"]


def sla(items):
    od = [r for r in items if r.get("sla_due") and r["sla_due"] < today() and r.get("step") not in ("approved", "rejected")]
    return [f"OVERDUE {r['process']} (requester {r.get('requester', '?')}, due {r['sla_due']}, at {r.get('step')})" for r in od] or ["nothing past its SLA"]


S = {
 "contacts": R("contacts", "Contacts", "contact", "name*; company; role; email: email; phone: phone; stage: choice(lead|active|customer|inactive)=lead; last_contact: date; tags: tags; notes: long",
               status="stage", done=("inactive",), list_cols=("name", "company", "email", "stage")),
 "workplace": R("bookings", "Workplace bookings", "booking", "resource*; kind: choice(desk|room|equipment|parking)=desk; person*; date: date*; from; to; status: choice(requested|confirmed|cancelled)=requested",
                status="status", done=("cancelled",), report=booking_conflicts, report_label="Double-booking check", list_cols=("resource", "person", "date", "from", "status")),
 "team": R("team", "Team", "team member", "name*; role; team; manager; location; start_date: date; status: choice(active|leave|onboarding|offboarded)=active; skills: tags; notes: long",
           status="status", done=("offboarded",), list_cols=("name", "role", "team", "status")),
 "docmgmt": R("documents", "Document register", "document", "title*; doc_type: choice(policy|contract|report|manual|other)=other; version=1.0; owner; status: choice(draft|review|approved|archived)=draft; review_by: date; retention_years: number; tags: tags",
              status="status", done=("approved", "archived"), due="review_by", list_cols=("title", "doc_type", "version", "status")),
 "tasks": R("tasks", "Tasks", "task", "title*; project; assignee; priority: choice(low|medium|high|urgent)=medium; status: choice(todo|doing|blocked|done)=todo; due: date; est_hours: number; notes: long",
            status="status", done=("done",), due="due", list_cols=("title", "assignee", "priority", "status", "due")),
 "planner": R("plan", "Plan", "task", "task*; owner; start: date; end: date; status: choice(planned|active|blocked|done)=planned; depends_on; percent: percent",
              status="status", done=("done",), due="end", start="start", list_cols=("task", "owner", "start", "end", "status")),
 "projects": R("projects", "Projects", "project", "name*; owner; client; budget: money; spent: money; start: date; end: date; status: choice(proposed|active|on-hold|done)=proposed; risk: choice(low|medium|high)=low; remaining: money",
               calc=("remaining=budget - spent",), status="status", done=("done",), amount="budget", due="end", start="start", report=portfolio, report_label="Budget health", list_cols=("name", "owner", "budget", "remaining", "status")),
 "meetings": R("meetings", "Meetings", "meeting", "title*; host; date: date; time; duration_min: number=30; participants: long; agenda: long; link: url; status: choice(scheduled|held|cancelled)=scheduled",
               status="status", done=("held", "cancelled"), due="date", list_cols=("title", "host", "date", "time", "status"),
               scope="Control plane only: scheduling, roster, agenda, notes. KOS apps cannot carry audio or video, so there is no call."),
 "webinars": R("webinars", "Webinars", "session", "title*; presenter; date: date; time; capacity: number; registered: number; attended: number; attendance_pct: number; qa_notes: long; status: choice(planned|live|done)=planned",
               calc=("attendance_pct=IF(registered>0,ROUND(attended/registered*100,1),0)",), status="status", done=("done",), due="date",
               scope="Control plane only: sessions, registration counts, attendance and Q&A notes. No streaming."),
 "rooms": R("rooms", "Meeting rooms", "room", "room*; building; capacity: number; equipment: tags; status: choice(open|maintenance)=open; booked_by; date: date; slot",
            status="status", done=(), list_cols=("room", "building", "capacity", "status"), scope="Room registry and booking list. No audio/video."),
 "videos": R("videos", "Video library", "video", "title*; duration; uploader; visibility: choice(private|unlisted|public)=private; tags: tags; views: number; url: url; status: choice(draft|published)=draft",
             status="status", done=("published",), amount="views", list_cols=("title", "visibility", "views", "status"), scope="A catalogue of videos (metadata, links, visibility, view counts). It does not store or stream video."),
 "photos": R("photos", "Photos", "photo", "file*; album; taken: date; place; camera; rating: number; tags: tags; notes: long",
             list_cols=("file", "album", "taken", "rating"), group="album", scope="A catalogue of photo metadata. It does not store or display pictures."),
 "edl": R("edl", "Edit decision list", "clip", "clip*; source; track: choice(V1|V2|A1|A2)=V1; tc_in*; tc_out*; transition: choice(cut|dissolve)=cut; notes",
          report=lambda items: __import__("kos.office.extras", fromlist=["edl"]).edl(items), report_label="EDL (CMX-style)", list_cols=("clip", "track", "tc_in", "tc_out", "transition"),
          scope="Plans an edit as a timeline and exports an EDL for a real editor. It does not decode or render video."),
 "recordings": R("recordings", "Recordings", "recording", "title*; date: date; recorded_by; length; location; consent: bool=no; transcript: choice(none|pending|done)=none; retention_until: date; notes: long",
                 status="transcript", done=("done",), due="retention_until", scope="A register of meeting recordings (consent, transcript status, retention). It does not record audio."),
 "assignments": R("assign", "Assignments", "task", "task*; assignee*; assigned_by; priority: choice(low|medium|high)=medium; due: date; status: choice(assigned|accepted|in-progress|done|declined)=assigned; workload_h: number",
                  status="status", done=("done", "declined"), due="due", report=workload, report_label="Workload by person", list_cols=("task", "assignee", "priority", "due", "status")),
 "resources": R("alloc", "Allocations", "allocation", "person*; project*; week: date; hours: number; role", amount="hours", group="person", report=utilization, report_label="Utilisation (40 h week)", list_cols=("person", "project", "week", "hours")),
 "time": R("time", "Time entries", "entry", "date: date*; project*; task; hours: number*; billable: bool=yes; rate: money; value: money",
           calc=('value=IF(billable="yes",hours*rate,0)',), amount="hours", group="project", list_cols=("date", "project", "hours", "value")),
 "engagement": R("engage", "Engagement", "entry", "kind: choice(pulse|recognition|feedback|suggestion)=pulse; from; to; score: number; message: long; status: choice(new|reviewed|actioned)=new",
                 status="status", done=("actioned",), group="kind", list_cols=("kind", "from", "to", "score", "status")),
 "courses": R("courses", "Courses", "course", "title*; code; instructor; level: choice(intro|intermediate|advanced)=intro; hours: number; start: date; status: choice(draft|open|running|done)=draft; description: long",
              status="status", done=("done",), list_cols=("title", "code", "instructor", "status")),
 "learners": R("learners", "Learners", "learner", "name*; email: email; course; progress: percent; status: choice(enrolled|active|completed|dropped)=enrolled; enrolled_on: date",
               status="status", done=("completed", "dropped"), list_cols=("name", "course", "progress", "status")),
 "students": R("students", "Students", "student", "name*; grade; guardian; contact: phone; notes: long; status: choice(active|transferred|graduated)=active", status="status", done=("graduated", "transferred")),
 "attendance": R("attend", "Attendance", "mark", "date: date*; student*; status: choice(present|absent|late|excused)=present; note", status="status", done=("present",), group="student", list_cols=("date", "student", "status")),
 "homework": R("homework", "Assignments", "assignment", "title*; course; due: date; points: number; status: choice(draft|published|closed)=draft; submissions: number; graded: number; instructions: long",
               status="status", done=("closed",), due="due", list_cols=("title", "course", "due", "submissions", "status")),
 "identities": R("identities", "Identities", "identity", "person*; user_id*; email: email; department; status: choice(pending|active|suspended|terminated)=pending; roles: tags; mfa: bool=no; last_review: date; manager",
                 status="status", done=("terminated",), list_cols=("person", "user_id", "department", "status", "mfa"), scope="An identity register (joiner/mover/leaver, reviews). It does not authenticate anyone: see the Authentication System."),
 "accounts": R("accounts", "User accounts", "account", "username*; full_name; email: email; status: choice(active|locked|disabled)=active; created: date; last_login: date; groups: tags; password_expires: date",
               status="status", done=("disabled",), due="password_expires", list_cols=("username", "full_name", "status", "last_login")),
 "devices": R("devices", "Devices", "device", "device*; kind: choice(laptop|phone|tablet|server|iot)=laptop; owner; os; os_version; encrypted: bool=no; status: choice(in-stock|assigned|repair|retired)=in-stock; last_seen: date; serial",
              status="status", done=("retired",), list_cols=("device", "kind", "owner", "encrypted", "status"), scope="An inventory and compliance register for devices. It does not manage or control any device."),
 "apps": R("apps", "Applications", "application", "app*; vendor; version; owner; criticality: choice(low|medium|high|critical)=medium; status: choice(evaluating|approved|deprecated|retired)=evaluating; renewal: date; cost: money; data_class: choice(public|internal|confidential|restricted)=internal",
           status="status", done=("retired",), amount="cost", due="renewal", list_cols=("app", "vendor", "criticality", "status")),
 "incidents": R("incidents", "Incidents", "incident", "title*; severity: choice(low|medium|high|critical)=medium; source; detected: date; status: choice(open|investigating|contained|closed)=open; owner; notes: long",
                status="status", done=("closed",), group="severity", list_cols=("title", "severity", "detected", "status")),
 "governance": R("governance", "Data assets", "asset", "asset*; owner; steward; classification: choice(public|internal|confidential|restricted)=internal; source_system; quality_score: percent; status: choice(proposed|approved|deprecated)=proposed; last_review: date",
                 status="status", done=("approved",), group="classification", list_cols=("asset", "owner", "classification", "quality_score", "status")),
 "privacy": R("privacy", "Privacy register", "item", "item*; kind: choice(processing-activity|DSAR|breach|DPIA)=DSAR; subject; received: date; due: date; status: choice(open|in-progress|done)=open; legal_basis; notes: long",
              status="status", done=("done",), due="due", list_cols=("item", "kind", "due", "status")),
 "compliance": R("controls", "Controls", "control", "control*; framework: choice(SOC2|ISO27001|GDPR|HIPAA|PCI|other)=SOC2; owner; status: choice(not-started|in-progress|implemented|verified)=not-started; evidence: url; next_review: date",
                 status="status", done=("implemented", "verified"), due="next_review", group="framework", report=coverage, report_label="Coverage by framework", list_cols=("control", "framework", "owner", "status")),
 "retention": R("retention", "Retention schedule", "dataset", "dataset*; class; created: date*; retain_days: number*; legal_hold: bool=no; expires: date",
                calc=("expires=DATEADD(created,retain_days)",), due="expires", report=disposal_due, report_label="Disposal due", list_cols=("dataset", "created", "retain_days", "expires", "legal_hold")),
 "backups": R("backups", "Backup jobs", "job", "job*; source; destination; schedule; kind: choice(full|incremental|differential)=full; last_run: date; last_result: choice(ok|failed|never)=never; retention_days: number; verified: bool=no",
              status="last_result", done=("ok",), report=backup_health, report_label="Backup health", list_cols=("job", "kind", "last_run", "last_result", "verified"), scope="A register of backup jobs, results and restore tests. Apps cannot read your files, so it does not copy any."),
 "recovery": R("recovery", "Recovery requests", "request", "request*; requested_by; item; restore_point: date; status: choice(requested|approved|restoring|verified|failed)=requested; rto_hours: number; opened: date; notes: long",
               status="status", done=("verified", "failed"), list_cols=("request", "item", "restore_point", "status"), scope="Tracks restore requests and their approval/verification. It does not restore data itself."),
 "archive": R("archive", "Archive register", "dataset", "dataset*; archived_on: date; location; size_mb: number; retention_years: number; format; status: choice(pending|archived|verified|purged)=pending; checksum",
              status="status", done=("verified", "purged"), amount="size_mb", list_cols=("dataset", "archived_on", "size_mb", "status")),
 "regions": R("regions", "Data residency", "dataset", "dataset*; owner; stored_region: choice(us|eu|uk|apac|other)=us; allowed_regions*; compliant",
              calc=('compliant=IF(CONTAINS(allowed_regions,stored_region),"yes","VIOLATION")',), group="stored_region", report=region_violations, report_label="Residency violations", list_cols=("dataset", "stored_region", "allowed_regions", "compliant")),
 "subscriptions": R("subs", "Subscriptions", "subscription", "service*; vendor; plan; cost: money*; cycle: choice(monthly|yearly)=monthly; renews: date; owner; status: choice(active|trial|cancelled)=active; monthly: money",
                    calc=('monthly=IF(cycle="yearly",ROUND(cost/12,2),cost)',), status="status", done=("cancelled",), amount="monthly", due="renews", list_cols=("service", "cost", "cycle", "renews", "status")),
 "licenses": R("licenses", "Licences", "licence", "product*; vendor; seats: number*; used: number; expires: date; cost: money; free: number; utilization_pct: number",
               calc=("free=seats-used", "utilization_pct=IF(seats>0,ROUND(used/seats*100,0),0)"), amount="cost", due="expires", report=license_risk, report_label="Licence risk", list_cols=("product", "seats", "used", "utilization_pct", "expires")),
 "groups": R("groups", "Groups", "group", "group*; kind: choice(security|distribution|team|project)=team; owner; members: long; description; status: choice(active|archived)=active", status="status", done=("archived",), group="kind"),
 "directory": R("directory", "Directory", "entry", "dn*; cn; type: choice(person|group|org-unit|device|service)=person; parent; mail: email; attributes: long", group="type", list_cols=("dn", "cn", "type", "parent")),
 "extensions": R("extensions", "Extensions", "extension", "name*; publisher; version; category; rating: number; installs: number; status: choice(listed|installed|disabled|removed)=listed; permissions: tags; price: money",
                 status="status", done=("removed",), amount="installs", list_cols=("name", "publisher", "rating", "status"), scope="A catalogue and installation register. It does not download, host or run extensions."),
 "marketplace": R("market", "Applications", "listing", "name*; vendor; version; category; rating: number; price: money; status: choice(listed|trial|purchased|retired)=listed; url: url",
                  status="status", done=("retired",), amount="price", list_cols=("name", "vendor", "rating", "price", "status"), scope="A catalogue and purchase register. It does not host or run applications."),
 "plugins": R("plugins", "Plugins", "plugin", "plugin*; version; source; enabled: bool=yes; permissions: tags; last_update: date; status: choice(ok|update-available|error)=ok", status="status", done=("ok",), list_cols=("plugin", "version", "enabled", "status")),
 "addons": R("addons", "Add-ons", "add-on", "addon*; host_app; version; enabled: bool=yes; permissions: tags; last_update: date; status: choice(ok|update-available|error)=ok", status="status", done=("ok",), list_cols=("addon", "host_app", "version", "enabled", "status")),
 "integrations": R("integrations", "Integrations", "integration", "name*; system_a; system_b; kind: choice(api|webhook|file|database)=api; status: choice(planned|active|failing|retired)=planned; owner; last_sync: date; notes: long",
                   status="status", done=("retired",), list_cols=("name", "system_a", "system_b", "kind", "status")),
 "sharedfiles": R("shares", "Shares", "share", "file*; owner; shared_with: tags; permission: choice(view|comment|edit)=view; link_expires: date; status: choice(active|expired|revoked)=active",
                  status="status", done=("expired", "revoked"), due="link_expires", list_cols=("file", "owner", "permission", "link_expires", "status"), scope="Tracks who a file is shared with and until when. It does not host or transfer files."),
 "sharedspaces": R("spaces", "Workspaces", "workspace", "workspace*; owner; members: tags; quota_mb: number; used_mb: number; status: choice(active|archived)=active; created: date; pct: number",
                   calc=("pct=IF(quota_mb>0,ROUND(used_mb/quota_mb*100,0),0)",), status="status", done=("archived",), list_cols=("workspace", "owner", "quota_mb", "pct", "status")),
 "assets": R("assets", "Digital assets", "asset", "asset*; kind: choice(image|video|audio|document|font|other)=image; tags: tags; license; usage_rights; expires: date; owner; status: choice(draft|approved|retired)=draft; location",
             status="status", done=("retired",), due="expires", group="kind", list_cols=("asset", "kind", "license", "expires", "status"), scope="A catalogue of asset metadata and usage rights. It does not store the files."),
 "processes": R("processes", "Approvals", "request", "process*; step: choice(submitted|manager-review|finance-review|approved|rejected)=submitted; requester; amount: money; submitted: date; sla_due: date; notes: long",
                status="step", done=("approved", "rejected"), amount="amount", due="sla_due", report=sla, report_label="SLA breaches", list_cols=("process", "requester", "amount", "step", "sla_due")),
}
