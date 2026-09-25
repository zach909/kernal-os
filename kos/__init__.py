"""KOS userland: the security layer that sits on top of the Linux kernel.

Design rule that every module follows: nothing privileged happens without the
owner's password being typed for *that* action. There are no background
services, no cached sessions and no non-interactive password input.
"""

__version__ = "0.1.0"
