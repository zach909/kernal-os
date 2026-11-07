"""kos.office - the productivity suite's shared library.

Apps in the suite are ordinary sandboxed KOS apps. They import from here
(``kos`` is on their import path, like ``kos.sdk``), draw with ``screen``
commands, and keep their data with the ``vault`` (``storage`` permission).
"""
