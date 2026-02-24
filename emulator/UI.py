import sys
import termios
import tty
import select
import time
import shutil
import re
from threading import Thread, Lock
from collections import deque


REFRESH_RATE = 0.05
LOG_HISTORY = 300

ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")


def strip_ansi(text: str) -> str:
    return ANSI_RE.sub("", text)


def visible_len(text: str) -> int:
    return len(strip_ansi(text))


def pad_visible(text: str, width: int) -> str:
    vlen = visible_len(text)
    if vlen < width:
        return text + " " * (width - vlen)
    return text[:width]


class Terminal:
    def __init__(self):
        self.fd = sys.stdin.fileno()
        self.old = termios.tcgetattr(self.fd)

    def __enter__(self):
        tty.setcbreak(self.fd)
        print("\033[?25l", end="")  # hide cursor
        print("\033[2J", end="")    # clear once
        return self

    def __exit__(self, *args):
        termios.tcsetattr(self.fd, termios.TCSADRAIN, self.old)
        print("\033[0m\033[?25h")   # reset + show cursor
        print("\033[H", end="")

    def get_key(self):
        if select.select([sys.stdin], [], [], 0)[0]:
            return sys.stdin.read(1)
        return None


class UI:
    def __init__(self):
        self.running = True
        self.show_code = True
        self.show_state = True
        self.show_hw = True

        self.log = deque(maxlen=LOG_HISTORY)
        self.lock = Lock()

        self.prev_rows = {}

        self._start_log_thread()

    # ---------------- LOG GENERATOR ---------------- #

    def _start_log_thread(self):
        def worker():
            i = 0
            while self.running:
                with self.lock:
                    self.log.appendleft(
                        f"[{i:04}] 0x0800{i:04x}  LDR R0, [R1]"
                    )
                i += 1
                time.sleep(0.12)

        Thread(target=worker, daemon=True).start()

    # ---------------- BOX RENDERING ---------------- #

    def render_box(self, rows, x, y, w, h, title, lines, fade=False):
        if w < 4 or h < 3:
            return

        # Top border
        rows[y] = rows.get(y, {})
        rows[y][x] = "╭" + "─" * (w - 2) + "╮"

        # Title
        rows[y][x + 2] = title[: w - 4]

        # Bottom border
        rows[y + h - 1] = rows.get(y + h - 1, {})
        rows[y + h - 1][x] = "╰" + "─" * (w - 2) + "╯"

        # Side borders
        for i in range(1, h - 1):
            row = y + i
            rows[row] = rows.get(row, {})
            rows[row][x] = "│"
            rows[row][x + w - 1] = "│"

        # Content
        for i in range(min(len(lines), h - 2)):
            raw = lines[i][: w - 2]

            if fade:
                shade = 255 - min(i * 2, 23)
                raw = f"\033[38;5;{shade}m{raw}\033[0m"

            padded = pad_visible(raw, w - 2)

            row = y + 1 + i
            rows[row] = rows.get(row, {})
            rows[row][x + 1] = padded

    # ---------------- FRAME RENDER ---------------- #

    def render(self):
        width, height = shutil.get_terminal_size()
        new_rows = {}

        left_w = width // 2 if self.show_code else 0
        right_w = width - left_w

        right_top_h = height // 2 if self.show_state else 0
        right_bottom_h = height - right_top_h

        if self.show_code:
            with self.lock:
                lines = list(self.log)
            self.render_box(
                new_rows,
                1,
                1,
                left_w - 1,
                height - 1,
                " code ",
                lines,
                fade=True,
            )

        if self.show_state:
            state_lines = [
                "PC: 0x08000400",
                "SP: 0x2000FFFC",
                "LR: 0xFFFFFFF9",
                "R0: 0x00000000",
                "R1: 0x00000001",
            ]
            self.render_box(
                new_rows,
                left_w + 1,
                1,
                right_w - 1,
                right_top_h - 1,
                " state ",
                state_lines,
            )

        if self.show_hw:
            hw_lines = [
                "IRQ Pending: 4",
                "IRQ Active: -1",
                "SysTick: enabled",
                "NVIC: 32 lines",
            ]
            self.render_box(
                new_rows,
                left_w + 1,
                right_top_h + 1,
                right_w - 1,
                right_bottom_h - 1,
                " hardware ",
                hw_lines,
            )

        # -------- LINE-BASED DIFF -------- #

        for row, cols in new_rows.items():
            for col, text in cols.items():
                prev = self.prev_rows.get(row, {}).get(col)
                if prev != text:
                    print(f"\033[{row};{col}H{text}", end="")

        self.prev_rows = new_rows
        sys.stdout.flush()

    # ---------------- KEY HANDLING ---------------- #

    def handle_key(self, key):
        if key == "q":
            self.running = False
        elif key == "c":
            self.show_code = not self.show_code
        elif key == "s":
            self.show_state = not self.show_state
        elif key == "h":
            self.show_hw = not self.show_hw

    # ---------------- MAIN LOOP ---------------- #

    def run(self):
        with Terminal() as term:
            while self.running:
                key = term.get_key()
                if key:
                    self.handle_key(key)

                self.render()
                time.sleep(REFRESH_RATE)


if __name__ == "__main__":
    UI().run()