"""The core's side of the KOS kernel: kos/kernel.py, kos/firewall.py, and how the sandbox,
the launch path and init use them. The kernel module itself is tested by booting it
(kernel/test/run.sh); here the securityfs directory and prctl are fakes, so every refusal can
be checked without a patched kernel.

Where a refusal is tested, the matching acceptance is next to it, so a pass means the rule
is what said no and not a broken fixture."""

from __future__ import annotations

import json
import os
import sys
import tempfile
import threading
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from kos import firewall, init, kernel  # noqa: E402
from kos.auth import AuditLog  # noqa: E402
from kos.paths import Paths  # noqa: E402
from kos.sandbox import SandboxError, SandboxPolicy  # noqa: E402

KEY = b"k" * 32


class FakeSfs:
    """A securityfs directory the test can fill in, and a prctl that plays the module."""

    def __init__(self, role="core", status="kos-lsm 1\ncore=claimed\nrules=0\nlogged=0\ndropped=0\n"):
        self.dir = Path(tempfile.mkdtemp())
        (self.dir / "status").write_text(status)
        (self.dir / "rules").write_text("")
        (self.dir / "log").write_text("")
        self.calls: list = []
        self.role = role

    def prctl(self, option, arg2=0):
        self.calls.append((option, arg2))
        if option == kernel.PR_STATUS:
            return {"core": kernel.STATUS_CORE, "app": 7, "none": 0}[self.role]
        if option == kernel.PR_CLAIM_CORE:
            if self.role != "core":
                raise OSError(1, "Operation not permitted")
            return 0
        if option == kernel.PR_CONFINE:
            if self.role != "core":
                raise OSError(1, "Operation not permitted")
            return 0
        raise OSError(22, "Invalid argument")

    def kernel(self, **kw) -> kernel.Kernel:
        return kernel.Kernel(self.dir, self.prctl, cmdline=kw.pop("cmdline", self.dir / "cmdline"),
                             environ=kw.pop("environ", {}))


class TestRuleChecks(unittest.TestCase):
    def test_a_typed_out_rule_is_accepted(self):
        r = kernel.check_rule(5, "tcp", "connect", "93.184.216.34", 443)
        self.assertEqual(r.line(), "allow 5 tcp connect 93.184.216.34 443")
        self.assertEqual(kernel.check_rule(5, "udp", "listen", "0.0.0.0", 5353).host, "0.0.0.0")
        self.assertEqual(kernel.check_rule(5, "tcp", "connect", "2001:DB8::1", 443).host, "2001:db8::1")

    def test_everything_that_is_not_one_host_one_port_is_refused(self):
        bad = [
            (5, "tcp", "connect", "example.com", 443),            # a name: resolving is a connection
            (5, "tcp", "connect", "10.0.0.0/8", 443),             # a range
            (5, "tcp", "connect", "*", 443),                      # a wildcard
            (5, "tcp", "connect", "", 443),
            (5, "tcp", "connect", "127.0.0.1 ", 443),             # trailing space
            (5, "tcp", "connect", "fe80::1%eth0", 443),           # scope id
            (5, "tcp", "connect", "0.0.0.0", 443),                # connect to 'unspecified'
            (5, "tcp", "connect", "224.0.0.1", 443),              # multicast
            (5, "tcp", "connect", "127.0.0.1", 0),                # 'any port'
            (5, "tcp", "connect", "127.0.0.1", 65536),
            (5, "tcp", "connect", "127.0.0.1", "80"),
            (5, "tcp", "connect", "127.0.0.1", True),
            (5, "icmp", "connect", "127.0.0.1", 80),
            (5, "tcp", "bind", "127.0.0.1", 80),
            (0, "tcp", "connect", "127.0.0.1", 80),
            (kernel.APP_MAX + 1, "tcp", "connect", "127.0.0.1", 80),
            ("5", "tcp", "connect", "127.0.0.1", 80),
            (5, "tcp", "connect", "127.0.0.1\n", 80),
            (5, "tcp", "connect", "１２７.0.0.1", 80),           # full-width digits
        ]
        for args in bad:
            with self.subTest(args=args):
                with self.assertRaises(kernel.KernelError):
                    kernel.check_rule(*args)

    def test_the_fake_kernel_gets_exactly_one_rule_per_write(self):
        sfs = FakeSfs()
        k = sfs.kernel()
        k.allow(kernel.check_rule(5, "tcp", "connect", "127.0.0.1", 9000))
        self.assertEqual((sfs.dir / "rules").read_text(), "allow 5 tcp connect 127.0.0.1 9000")
        (sfs.dir / "rules").write_text("")      # a real securityfs file takes each write as a new command
        k.revoke_app(5)
        self.assertEqual((sfs.dir / "rules").read_text(), "revoke-app 5")

    def test_a_rule_that_was_not_checked_is_still_refused_before_it_is_written(self):
        sfs = FakeSfs()
        k = sfs.kernel()
        with self.assertRaises(kernel.KernelError):
            k.allow(kernel.Rule(5, "tcp", "connect", "example.com", 443))
        with self.assertRaises(kernel.KernelError):
            k.revoke_app(0)
        self.assertEqual((sfs.dir / "rules").read_text(), "")


class TestKernelFacts(unittest.TestCase):
    def test_roles(self):
        self.assertEqual(FakeSfs("core").kernel().role(), "core")
        self.assertTrue(FakeSfs("core").kernel().can_confine())
        self.assertEqual(FakeSfs("app").kernel().role(), "app")
        self.assertFalse(FakeSfs("app").kernel().can_confine())

    def test_no_module_means_no_role_and_no_confinement(self):
        k = kernel.Kernel(Path(tempfile.mkdtemp()) / "nothing", lambda *a: 0)
        self.assertFalse(k.present())
        self.assertEqual(k.role(), "none")
        self.assertFalse(k.can_confine())
        with self.assertRaises(kernel.KernelError):
            k.status()

    def test_status_is_read_from_the_module(self):
        s = FakeSfs().kernel().status()
        self.assertEqual((s["core"], s["rules"]), ("claimed", 0))

    def test_required_comes_from_the_signed_command_line_or_the_environment(self):
        sfs = FakeSfs()
        (sfs.dir / "cmdline").write_text("quiet kos.require_kernel=1 loglevel=1\n")
        self.assertTrue(sfs.kernel().required())
        (sfs.dir / "cmdline").write_text("quiet kos.require_kernel=10 loglevel=1\n")
        self.assertFalse(sfs.kernel().required(), "a longer value is not the setting")
        (sfs.dir / "cmdline").write_text("quiet\n")
        self.assertFalse(sfs.kernel().required())
        self.assertTrue(sfs.kernel(environ={"KOS_REQUIRE_KERNEL": "1"}).required())
        with mock.patch("os.getpid", return_value=1):
            self.assertFalse(sfs.kernel(environ={"KOS_REQUIRE_KERNEL": "1"}).required(),
                             "PID 1 is not steered by its environment")

    def test_confine_and_claim_report_the_kernels_refusal(self):
        app = FakeSfs("app").kernel()
        with self.assertRaises(kernel.KernelError):
            app.claim_core()
        with self.assertRaises(kernel.KernelError):
            app.confine(7)
        core = FakeSfs("core")
        core.kernel().confine(9)
        self.assertEqual(core.calls[-1], (kernel.PR_CONFINE, 9))
        for bad in (0, -1, kernel.APP_MAX + 1, "7", None):
            with self.assertRaises(kernel.KernelError):
                core.kernel().confine(bad)


class TestKernelLog(unittest.TestCase):
    def test_the_log_is_parsed_strictly(self):
        sfs = FakeSfs()
        (sfs.dir / "log").write_text(
            "dropped 3\n"
            "10 allow app=8 connect tcp 127.0.0.1 9000\n"
            "11 deny app=7 create family=2 type=1 protocol=0\n"
            "12 deny app=7 open device 5:1\n"
            "garbage\n"
            "13 maybe app=7 connect tcp 1.2.3.4 80\n"                # not allow/deny
            "14 deny app=7 \x1b[31mred\n"                             # control character
            "15 deny app=x connect tcp 1.2.3.4 80\n")                  # not a number
        lines, dropped = sfs.kernel().drain_log()
        self.assertEqual(dropped, 3)
        self.assertEqual([(l.seq, l.verdict, l.app) for l in lines], [(10, "allow", 8), (11, "deny", 7), (12, "deny", 7)])
        self.assertEqual(lines[0].detail, "connect tcp 127.0.0.1 9000")


class TestAppIds(unittest.TestCase):
    def test_ids_are_never_reused(self):
        state = Path(tempfile.mkdtemp())
        ids = [kernel.AppIds(state).next() for _ in range(5)]
        self.assertEqual(ids, [1, 2, 3, 4, 5])
        self.assertEqual(kernel.AppIds(state).next(), 6, "a new object continues; it does not restart")

    def test_ids_stay_unique_when_many_launch_at_once(self):
        state, got, lock = Path(tempfile.mkdtemp()), [], threading.Lock()

        def take():
            for _ in range(20):
                n = kernel.AppIds(state).next()
                with lock:
                    got.append(n)
        ts = [threading.Thread(target=take) for _ in range(6)]
        [t.start() for t in ts]
        [t.join() for t in ts]
        self.assertEqual(len(got), len(set(got)))
        self.assertEqual(sorted(got), list(range(1, 121)))

    def test_a_damaged_counter_does_not_hand_out_a_low_id_twice(self):
        state = Path(tempfile.mkdtemp())
        a = kernel.AppIds(state)
        a.next()
        a.file.write_text("not a number")
        self.assertEqual(a.next(), 1, "unreadable resets; documented: ids are per-boot unique via the kernel's table, "
                                       "and the rules are revoked at exit")

    def test_counter_file_is_private(self):
        state = Path(tempfile.mkdtemp())
        kernel.AppIds(state).next()
        self.assertEqual(oct(os.stat(state / "kernel" / "next-app-id").st_mode & 0o777), "0o600")


class FwEnv(unittest.TestCase):
    def setUp(self):
        self.root = Path(tempfile.mkdtemp())
        self.paths = Paths(self.root)
        self.paths.ensure()
        self.store = firewall.FirewallStore(self.paths)


class TestFirewallStore(FwEnv):
    E = ("web", "tcp", "connect", "93.184.216.34", 443)

    def test_add_list_remove(self):
        e = firewall.check_entry(*self.E)
        self.assertEqual(self.store.load(KEY), ([], "empty"))
        self.assertTrue(self.store.add(KEY, e))
        self.assertFalse(self.store.add(KEY, e), "the same rule twice is one rule")
        self.assertEqual(self.store.load(KEY), ([e], "ok"))
        self.assertTrue(self.store.remove(KEY, e))
        self.assertFalse(self.store.remove(KEY, e))
        self.assertEqual(self.store.load(KEY)[0], [])

    def test_a_rule_file_made_without_the_password_is_not_believed(self):
        e = firewall.check_entry(*self.E)
        self.store.add(KEY, e)
        self.assertEqual(self.store.load(b"x" * 32), ([], "tampered"), "wrong key")
        raw = json.loads(self.store.file.read_text())
        raw["rules"].append({"app": "evil", "proto": "tcp", "direction": "connect", "host": "6.6.6.6", "port": 80})
        self.store.file.write_text(json.dumps(raw))
        self.assertEqual(self.store.load(KEY), ([], "tampered"), "an added rule breaks the seal")
        with self.assertRaises(firewall.FirewallError):
            self.store.add(KEY, e)
        with self.assertRaises(firewall.FirewallError):
            self.store.remove(KEY, e)

    def test_a_malformed_file_gives_deny_all(self):
        for text in ("", "not json", "[]", '{"rules": 5, "mac": "x"}', '{"rules": [{"app": 1}], "mac": "x"}',
                     json.dumps({"rules": [{"app": "web", "proto": "tcp", "direction": "connect",
                                            "host": "*", "port": 80}], "mac": "x"})):
            with self.subTest(text=text[:30]):
                self.store.file.parent.mkdir(parents=True, exist_ok=True)
                self.store.file.write_text(text)
                self.assertEqual(self.store.load(KEY), ([], "tampered"))

    def test_entries_are_checked_like_kernel_rules(self):
        for bad in (("web", "tcp", "connect", "example.com", 443), ("Web!", "tcp", "connect", "1.2.3.4", 443),
                    ("web", "tcp", "connect", "1.2.3.4", 0), ("../x", "tcp", "connect", "1.2.3.4", 1), (5, "tcp", "connect", "1.2.3.4", 1)):
            with self.subTest(bad=bad), self.assertRaises(firewall.FirewallError):
                firewall.check_entry(*bad)

    def test_the_file_is_private(self):
        self.store.add(KEY, firewall.check_entry(*self.E))
        self.assertEqual(oct(os.stat(self.store.file).st_mode & 0o777), "0o600")


class TestLaunch(FwEnv):
    def entries(self):
        for e in (("web", "tcp", "connect", "93.184.216.34", 443), ("web", "tcp", "listen", "127.0.0.1", 8080),
                  ("other", "tcp", "connect", "10.1.1.1", 22)):
            self.store.add(KEY, firewall.check_entry(*e))

    def test_a_stock_kernel_is_fine_unless_the_boot_requires_the_kernel(self):
        policy = SandboxPolicy(allow_network=True)
        none = kernel.Kernel(self.root / "no", lambda *a: 0, cmdline=self.root / "cmdline", environ={})
        self.assertEqual(firewall.prepare_launch(self.paths, "web", policy, KEY, none), 0)
        self.assertEqual(policy.kernel_app_id, 0)
        (self.root / "cmdline").write_text("kos.require_kernel=1")
        with self.assertRaises(SandboxError):
            firewall.prepare_launch(self.paths, "web", policy, KEY, none)

    def test_not_being_the_core_is_refused_when_required(self):
        sfs = FakeSfs("app")
        (sfs.dir / "cmdline").write_text("kos.require_kernel=1")
        with self.assertRaises(SandboxError):
            firewall.prepare_launch(self.paths, "web", SandboxPolicy(), KEY, sfs.kernel())

    def test_rules_reach_the_kernel_only_for_the_app_that_has_them_and_only_with_the_network_yes(self):
        self.entries()
        sfs = FakeSfs()
        written = []
        k = sfs.kernel()
        k._write_rule = written.append          # noqa: SLF001 - observing what the kernel would be told
        yes = SandboxPolicy(allow_network=True)
        app_id = firewall.prepare_launch(self.paths, "web", yes, KEY, k)
        self.assertEqual(yes.kernel_app_id, app_id)
        self.assertEqual(sorted(written), sorted([f"allow {app_id} tcp connect 93.184.216.34 443",
                                                  f"allow {app_id} tcp listen 127.0.0.1 8080"]))
        written.clear()
        no = SandboxPolicy(allow_network=False)
        firewall.prepare_launch(self.paths, "web", no, KEY, k)
        self.assertEqual(written, [], "the owner did not say yes to the network at this launch: no rules")
        self.assertGreater(no.kernel_app_id, 0, "but the app is still confined")
        written.clear()
        firewall.prepare_launch(self.paths, "nobody-listed", SandboxPolicy(allow_network=True), KEY, k)
        self.assertEqual(written, [])

    def test_a_tampered_rule_file_gives_the_app_no_rules_and_says_so(self):
        self.entries()
        sfs = FakeSfs()
        written = []
        k = sfs.kernel()
        k._write_rule = written.append          # noqa: SLF001
        raw = json.loads(self.store.file.read_text())
        raw["rules"].append({"app": "web", "proto": "tcp", "direction": "connect", "host": "6.6.6.6", "port": 80})
        self.store.file.write_text(json.dumps(raw))
        firewall.prepare_launch(self.paths, "web", SandboxPolicy(allow_network=True), KEY, k)
        self.assertEqual(written, [])
        entries = AuditLog(self.paths).entries()
        self.assertTrue(any(e.get("action") == "firewall.rules" and e.get("target") == "web"
                            and e.get("outcome") == "tampered" for e in entries), entries)

    def test_exit_takes_the_rules_back_and_copies_the_kernel_log_into_the_audit_log(self):
        self.entries()
        sfs = FakeSfs()
        k = sfs.kernel()
        written = []
        k._write_rule = written.append          # noqa: SLF001
        policy = SandboxPolicy(allow_network=True)
        app_id = firewall.prepare_launch(self.paths, "web", policy, KEY, k)
        (sfs.dir / "log").write_text(f"1 allow app={app_id} connect tcp 93.184.216.34 443\n"
                                     f"2 deny app={app_id} connect tcp 1.1.1.1 443\n")
        written.clear()
        policy.on_exit()
        self.assertEqual(written, [f"revoke-app {app_id}"])
        got = {(e["target"], e["outcome"]) for e in AuditLog(self.paths).entries() if e["action"].startswith("net.")}
        self.assertIn(("web: connect tcp 93.184.216.34 443", "allowed"), got)
        self.assertIn(("web: connect tcp 1.1.1.1 443", "blocked"), got)


class TestSandboxUsesTheKernel(unittest.TestCase):
    def test_when_required_an_app_without_a_kernel_id_does_not_start(self):
        k = kernel.Kernel(Path("/nonexistent"), lambda *a: 0, cmdline=Path("/nonexistent"), environ={"KOS_REQUIRE_KERNEL": "1"})
        with mock.patch.object(kernel, "default", return_value=k):
            with self.assertRaises(SandboxError):
                SandboxPolicy().probe()
            ok = SandboxPolicy(kernel_app_id=3)
            ok.probe()                               # confined by the kernel: allowed to go on

    def test_when_not_required_a_stock_kernel_still_runs_apps(self):
        k = kernel.Kernel(Path("/nonexistent"), lambda *a: 0, cmdline=Path("/nonexistent"), environ={})
        with mock.patch.object(kernel, "default", return_value=k):
            SandboxPolicy().probe()

    def test_the_child_confines_itself_before_anything_else(self):
        order = []
        sfs = FakeSfs()
        k = sfs.kernel()
        k.confine = lambda n: order.append(("confine", n))
        policy = SandboxPolicy(kernel_app_id=12, weak=True)
        policy._drop_root = staticmethod(lambda: order.append(("drop-root", None)))
        with mock.patch.object(kernel, "default", return_value=k), \
                mock.patch("kos.sandbox._libc") as libc, mock.patch("kos.sandbox.landlock_abi", return_value=0):
            libc.prctl.return_value = 0
            libc.unshare.return_value = 0
            with mock.patch.object(SandboxPolicy, "_landlock"), mock.patch.object(SandboxPolicy, "_seccomp"), \
                    mock.patch("resource.setrlimit"), mock.patch("os.umask"):
                policy.preexec()()
        self.assertEqual(order[0], ("confine", 12))
        self.assertIn(("drop-root", None), order)

    def test_a_kernel_that_refuses_to_confine_stops_the_launch(self):
        sfs = FakeSfs("app")                          # not the core: the kernel says no
        policy = SandboxPolicy(kernel_app_id=12, weak=True)
        with mock.patch.object(kernel, "default", return_value=sfs.kernel()):
            with self.assertRaises(SandboxError):
                policy.preexec()()


class TestInitClaimsTheCore(unittest.TestCase):
    class Say:
        def __init__(self): self.said = []
        def info(self, m): self.said.append(m)

    def setUp(self):
        self.paths = Paths(Path(tempfile.mkdtemp()))
        self.paths.ensure()

    def test_the_core_is_claimed_when_the_module_is_there(self):
        sfs = FakeSfs()
        self.assertTrue(init.kernel_gate(self.paths, self.Say(), sfs.kernel()))
        self.assertIn((kernel.PR_CLAIM_CORE, 0), sfs.calls)

    def test_a_stock_kernel_boots_with_a_warning_unless_required(self):
        say = self.Say()
        k = kernel.Kernel(Path("/nonexistent"), lambda *a: 0, cmdline=Path("/nonexistent"), environ={})
        self.assertFalse(init.kernel_gate(self.paths, say, k))
        self.assertIn("not the KOS kernel", "".join(say.said))

    def test_a_stock_kernel_stops_a_boot_that_requires_the_kernel(self):
        k = kernel.Kernel(Path("/nonexistent"), lambda *a: 0, cmdline=Path("/nonexistent"),
                          environ={"KOS_REQUIRE_KERNEL": "1"})
        say = self.Say()
        with self.assertRaises(SystemExit) as cm:
            init.kernel_gate(self.paths, say, k)
        self.assertEqual(cm.exception.code, 71)
        self.assertIn("requires it", "".join(say.said))

    def test_a_refused_claim_stops_a_boot_that_requires_the_kernel(self):
        sfs = FakeSfs("app")                          # the kernel refuses: someone already claimed it
        k = sfs.kernel(environ={"KOS_REQUIRE_KERNEL": "1"})
        with self.assertRaises(SystemExit):
            init.kernel_gate(self.paths, self.Say(), k)


class TestTheShippedKernelFiles(unittest.TestCase):
    """kernel/ is what makes this OS's kernel its own. These fail if the pieces stop agreeing."""
    K = Path(__file__).resolve().parent.parent / "kernel"

    def test_the_pinned_source_is_named_and_checksummed(self):
        import re
        ver = (self.K / "KERNEL_VERSION").read_text().strip()
        self.assertRegex(ver, r"^\d+\.\d+\.\d+$")
        self.assertRegex((self.K / "KERNEL_SHA256").read_text().strip(), r"^[0-9a-f]{64}$")
        patch = (self.K / "patches" / "0001-kos-lsm.patch").read_text()
        self.assertIn(f"Linux {ver}", patch, "the patch says which Linux it is made against")
        self.assertTrue(re.search(r"https://cdn\.kernel\.org", (self.K / "build.sh").read_text()))

    def test_the_patch_touches_only_what_a_new_lsm_needs(self):
        import re
        patch = (self.K / "patches" / "0001-kos-lsm.patch").read_text()
        files = set(re.findall(r"^\+\+\+ b/(\S+)", patch, re.M))
        self.assertEqual(files, {"include/uapi/linux/lsm.h", "include/linux/lsm_count.h", "security/Kconfig",
                                 "security/Makefile", "security/kos/Kconfig", "security/kos/Makefile",
                                 "security/kos/kos.c"})
        # an LSM may add hooks of its own; it must not edit what other code does
        removed = [l for l in patch.splitlines() if l.startswith("-") and not l.startswith("---")]
        self.assertTrue(all("bpf\"" in l or ",bpf" in l for l in removed), removed)

    def test_the_config_selects_the_module_and_really_can_switch_off_what_it_says(self):
        cfg = (self.K / "kos.config").read_text()
        self.assertIn("CONFIG_SECURITY_KOS=y", cfg)
        import re
        lsm = re.search(r'^CONFIG_LSM="([^"]+)"', cfg, re.M).group(1).split(",")
        self.assertIn("kos", lsm)
        self.assertLess(lsm.index("kos"), lsm.index("bpf"), "bpf stays last")
        for hidden in ("IO_URING", "X86_VSYSCALL_EMULATION"):         # only switchable with EXPERT: see build.sh
            if f"# CONFIG_{hidden} is not set" in cfg:
                self.assertIn("CONFIG_EXPERT=y", cfg, hidden)
        self.assertNotIn("CONFIG_PAGE_TABLE_ISOLATION=", cfg, "renamed in 6.x: MITIGATION_PAGE_TABLE_ISOLATION")

    def test_the_signed_command_line_requires_the_kos_kernel_and_names_the_module(self):
        cmd = (self.K / "cmdline.txt").read_text().split()
        self.assertIn("kos.require_kernel=1", cmd)
        lsm = next(w for w in cmd if w.startswith("lsm=")).split("=", 1)[1].split(",")
        self.assertIn("kos", lsm)
        self.assertIn("landlock", lsm)

    def test_the_scripts_are_executable_and_parse(self):
        import subprocess
        for f in (self.K / "build.sh", self.K / "test" / "run.sh"):
            self.assertTrue(os.access(f, os.X_OK), f)
            self.assertEqual(subprocess.run(["bash", "-n", str(f)], capture_output=True).returncode, 0, f)

    def test_the_test_program_refuses_what_the_rules_say_and_allows_the_matching_call(self):
        c = (self.K / "test" / "kos_lsm_test.c").read_text()
        for must in ("only PID 1 can claim the core", "an app cannot write firewall rules",
                     "app 7 with no rule cannot create a TCP socket", "an app cannot open a tty",
                     "AF_UNSPEC does not smuggle", "a wildcard host is refused", "a range is refused",
                     "trailing junk after an address is refused", "reading the log drains it",
                     "confinement survives fork and exec", "control: the core can create an inet socket"):
            self.assertIn(must, c)

    @unittest.skipUnless(os.environ.get("KOS_KERNEL_TEST") == "1",
                         "boots a real kernel under QEMU (about 2 minutes, downloads Linux): KOS_KERNEL_TEST=1")
    def test_boot_the_patched_kernel_and_run_the_module_checks(self):
        import subprocess
        r = subprocess.run([str(self.K / "test" / "run.sh")], capture_output=True, text=True, timeout=1500)
        self.assertEqual(r.returncode, 0, r.stdout[-2000:] + r.stderr[-2000:])
        self.assertRegex(r.stdout, r"\d+ checks passed, 0 failed")


if __name__ == "__main__":
    unittest.main()
