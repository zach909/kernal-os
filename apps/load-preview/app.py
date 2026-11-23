"""Load preview: a built-in test picture shown through the load effect, so you can see your settings work.
It reads the ``load-effect`` space (read access, granted by the owner) and draws only ``frame`` commands.
Key r replays the arrival. With 3D on, move the mouse: it is the vanishing point."""

from kos.sdk import App, Canvas

BG, PANEL, WIN, RED, GREEN, WHITE, GOLD = "#2a3a52", "#6a7fa0", "#46587a", "#d05050", "#50c070", "#f0f0f0", "#e8d040"
W, H = 60, 40
UI = "#101820"


def picture():
    g = [[PANEL] * W for _ in range(H)]

    def rect(x0, y0, x1, y1, c):
        for y in range(y0, y1):
            for x in range(x0, x1):
                g[y][x] = c
    rect(0, 0, W, H, BG)
    rect(4, 4, 56, 36, PANEL)
    rect(9, 9, 30, 20, RED)
    rect(35, 10, 50, 30, GREEN)
    rect(12, 12, 20, 17, WHITE)
    for y in range(22, 34):
        for x in range(8, 28):
            if (x - 17) ** 2 + (y - 28) ** 2 <= 25:
                g[y][x] = GOLD
    return g


def base(app):
    return Canvas().clear(UI).rect(0, 0, app.width, 18, "#1f3a5f").text(6, 5, "LOAD PREVIEW", "#ffffff")


def main():
    app = App()
    scene, fx, vp = None, None, None
    for ev in app.events():
        cmd = ev["cmd"]
        if cmd == "hello" or (cmd == "key" and ev["key"] == "r"):
            fx = app.load_effect()
            scale = max(1, min((app.width - 40) // W, (app.height - 60) // H))
            scene = app.scene(picture(), 20, 30, scale, ui_color=UI)
            app.show_scene(base(app), scene, vp, fx)
        elif cmd == "pointer" and scene is not None and fx and fx["three_d"]:
            vp = (ev["x"], ev["y"])
            app.show_scene(base(app), scene, vp, {**fx, "on": False})
