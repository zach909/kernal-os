"""The App Builder (``apps/app-builder``): a separate app that saves a checked draft in its own shared
folder. Driven through its real functions with a fake SDK; the draft is then packed through the real proof gate."""

import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from kos.kapp import KApp, pack  # noqa: E402

DIR = Path(__file__).resolve().parent.parent / "apps" / "app-builder"
spec = importlib.util.spec_from_file_location("app_builder", DIR / "app.py")
ab = importlib.util.module_from_spec(spec)
spec.loader.exec_module(ab)


class Fake:
    def __init__(self, refuse=False):
        self.store, self.refuse, self.vault_error = {}, refuse, ""

    def vault_put(self, key, value, space=None):
        assert space == ab.SPACE
        if self.refuse:
            self.vault_error = "no write access"
            return False
        self.store[key] = value
        return True


class TestAppBuilder(unittest.TestCase):
    def test_good_draft_is_saved_and_packs_through_the_proof_gate(self):
        app = Fake()
        self.assertIn("saved draft", ab.save(app, "my-tool", "Does a thing", ["tui", "graphical"]))
        m = json.loads(app.store["my-tool.manifest.json"])
        self.assertEqual((m["modes"], m["permissions"]), (["tui", "graphical"], []))
        with tempfile.TemporaryDirectory() as t:
            d = Path(t) / "my-tool"
            d.mkdir()
            (d / "manifest.json").write_text(app.store["my-tool.manifest.json"])
            (d / "app.py").write_text(app.store["my-tool.app.py"])
            pack(d, Path(t) / "x.kapp")
            self.assertEqual(KApp.from_file(Path(t) / "x.kapp").manifest.name, "my-tool")

    def test_hostile_input_is_refused_and_nothing_is_saved(self):
        for name, desc, modes in [("../x", "d", ["tui"]), ("Bad", "d", ["tui"]), ("kos", "d", ["tui"]),
                                  ("", "d", ["tui"]), ("a" * 33, "d", ["tui"]), ("ok", "", ["tui"]),
                                  ("ok", "x" * 201, ["tui"]), ("ok", "a\x1b[2Jb", ["tui"]),
                                  ("ok", "d", []), ("ok", "d", ["root"])]:
            app = Fake()
            self.assertNotIn("saved", ab.save(app, name, desc, modes))
            self.assertEqual(app.store, {}, (name, desc, modes))

    def test_refused_write_is_reported(self):
        self.assertIn("not saved", ab.save(Fake(refuse=True), "ok", "d", ["tui"]))

    def test_manifest_asks_for_one_folder_and_nothing_else(self):
        m = json.loads((DIR / "manifest.json").read_text())
        self.assertEqual(m["permissions"], ["owns:app-drafts"])


if __name__ == "__main__":
    unittest.main()
