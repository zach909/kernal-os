"""kosync - move a person's data between machines and between operating systems.

Two separate programs share one encrypted format:

* ``kosync.migrate``  - export everything to one encrypted bundle, import it on a machine running a
  different OS (file names are made legal for the new OS, nothing is overwritten, nothing is lost silently);
* ``kosync.sync``     - keep a folder identical on several machines through any dumb shared folder
  (USB stick, SMB share, a cloud-drive folder). The shared folder only ever sees ciphertext.

Runs on Linux, macOS and Windows with Python 3.9+ and the ``cryptography`` package. The byte-exact format is
in PROTOCOL.md so a native iPhone or Android client can be written against it.
"""

__version__ = "1.0"
