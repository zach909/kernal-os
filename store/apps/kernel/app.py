"""The kernel, as an app. KOS's own kernel layer (the sandbox, the cells, the kernel checks the
administrator keyboard depends on) stays in the OS, because an app cannot confine itself. What *is* an
app is the window onto it: this app has one permission, ``ask:kernel``, and so it can ask the OS exactly
one question - "what does this kernel protect, and which cells run?" - and show the answer.

It cannot start or stop a cell, touch a device or change a setting: the answer is data.

Keys: r ask again, Esc leave."""

from kos.sdk import App

LABELS = (("landlock_abi", "Landlock (file sandbox)"), ("seccomp_filter", "seccomp filter"),
          ("user_namespaces", "user namespaces"), ("kvm", "KVM (kernel cells)"),
          ("vhost_vsock", "vhost-vsock (cells)"), ("framebuffer", "framebuffer /dev/fb0"),
          ("evdev", "input devices (evdev)"))


def shown(value):
    if value is True:
        return "yes"
    if not value:
        return "NO"
    return f"yes (ABI {value})"


def lines(state):
    if state["kernel"] is None:
        return ["", "  asking the OS what the kernel protects...", ""]
    k = state["kernel"]
    prot = k.get("protections", {})
    out = [""]
    for key, label in LABELS:
        if key in prot:
            out.append(f"  {label:26} {shown(prot[key])}")
    out += ["", f"  {k.get('admin', '')}", ""]
    cells = k.get("cells", [])
    out.append("  kernel cells: " + ("none" if not cells else ""))
    for c in cells:
        out.append(f"    {c['name']:16} cid={c['cid']:<4} cpus={','.join(map(str, c['cpus']))} "
                   f"{c['memory_mb']}M {'running' if c['running'] else 'dead'}")
    out += ["", "  r ask again   Esc leave"]
    return out


def main():
    app = App()
    state = {"kernel": None}
    for ev in app.events():
        if ev["cmd"] == "hello":
            app.request_kernel()
        elif ev["cmd"] == "kernel":
            state["kernel"] = ev
        elif ev["cmd"] == "key":
            if ev["key"] == "r":
                state["kernel"] = None
                app.request_kernel()
            elif ev["key"] == "escape":
                app.exit(0)
        app.screen("Kernel", lines(state), "read-only")
