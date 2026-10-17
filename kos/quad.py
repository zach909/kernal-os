"""Quads: where a rectangle lands when a camera looks at it, and the way back.

A flat rectangle seen through a perspective camera is a quadrilateral on screen, and the map between the two is a homography. These
three functions are all the OS needs to turn a click on a drawn quad back into a position on the flat layer - no matter which interface
app drew it (3D, VR, ...). They do no drawing.
"""

from __future__ import annotations

from typing import Optional


def unproject_quad(quad, x: float, y: float, w: float, h: float) -> Optional[tuple[float, float]]:
    """Where on a ``w`` x ``h`` rectangle, drawn as ``quad`` (TL, TR, BR, BL on screen), is the screen point (x, y)? None if it is outside."""
    if not point_in_quad(quad, x, y):
        return None
    inv = unit_to_quad(quad)
    if inv is None:
        return None
    A, B, C, D, E, F, G, H, I = inv
    den = G * x + H * y + I
    if abs(den) < 1e-12:
        return None
    u, v = (A * x + B * y + C) / den, (D * x + E * y + F) / den
    if -0.001 <= u <= 1.001 and -0.001 <= v <= 1.001:
        return u * w, v * h
    return None


def unit_to_quad(q) -> Optional[tuple]:
    """The homography taking the unit square (0,0),(1,0),(1,1),(0,1) onto the quad ``q``, and its inverse as 9 numbers
    (screen -> unit square). None for a degenerate quad."""
    (x0, y0), (x1, y1), (x2, y2), (x3, y3) = q
    dx1, dx2, sx = x1 - x2, x3 - x2, x0 - x1 + x2 - x3
    dy1, dy2, sy = y1 - y2, y3 - y2, y0 - y1 + y2 - y3
    den = dx1 * dy2 - dx2 * dy1
    if abs(den) < 1e-9:
        return None
    g = (sx * dy2 - sy * dx2) / den
    h = (dx1 * sy - dy1 * sx) / den
    a, b, c = x1 - x0 + g * x1, x3 - x0 + h * x3, x0
    d, e, f = y1 - y0 + g * y1, y3 - y0 + h * y3, y0
    # inverse of [[a,b,c],[d,e,f],[g,h,1]] by the adjugate
    A, B, C = e - f * h, c * h - b, b * f - c * e
    D, E, F = f * g - d, a - c * g, c * d - a * f
    G, H, I = d * h - e * g, b * g - a * h, a * e - b * d
    return (A, B, C, D, E, F, G, H, I)


def polygon_area(q) -> float:
    return 0.5 * sum(q[i][0] * q[(i + 1) % len(q)][1] - q[(i + 1) % len(q)][0] * q[i][1] for i in range(len(q)))


def point_in_quad(q, x: float, y: float) -> bool:
    sign = 0
    for i in range(4):
        (ax, ay), (bx, by) = q[i], q[(i + 1) % 4]
        cr = (bx - ax) * (y - ay) - (by - ay) * (x - ax)
        if cr:
            s = 1 if cr > 0 else -1
            if sign and s != sign:
                return False
            sign = s
    return True
