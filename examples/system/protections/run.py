"""Launcher: npm runs this (see package.json), so every KOS app starts the same
way - ``npm run start``. It puts the KOS SDK and this app on the import path and
calls the app's entry point."""
import os
import sys

sys.path[:0] = [os.environ["KOS_SDK_DIR"], os.path.dirname(os.path.abspath(__file__))]
import app  # noqa: E402

sys.exit(getattr(app, "main")())
