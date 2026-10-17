"""The normal interface: the layers drawn as the flat glass desktop. (An app: ``interface-normal``.)"""

from __future__ import annotations

from kos.scenelib import Interface, Runner


class Flat(Interface):
    def render(self):
        return self.model.compose().copy(), [], []                # the click bubbles (an overlay layer) are composed in


def main() -> None:
    Runner(Flat).run()
