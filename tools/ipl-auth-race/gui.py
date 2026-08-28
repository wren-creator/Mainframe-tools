#!/usr/bin/env python3
"""Simple GUI for ipl-auth-race.

Pick a target, run the check, watch the console/probe stream, get a verdict, and save
the client HTML report. The engine runs on a background thread; UI updates arrive
through a queue drained on the Tk event loop.
"""
from __future__ import annotations

import asyncio
import queue
import threading
import tkinter as tk
from pathlib import Path
from tkinter import ttk, filedialog, messagebox

import engine
import report as report_mod

SEV_COLOR = {"critical": "#b3261e", "high": "#c2410c", "medium": "#b8860b",
             "low": "#3a7d34", "info": "#3a5f8a"}


class App:
    def __init__(self, root: tk.Tk):
        self.root = root
        root.title("IPL auth-race check")
        root.geometry("900x640")
        self.q: queue.Queue = queue.Queue()
        self.reports: list[dict] = []
        self.targets_file = tk.StringVar(value="targets.yaml")

        self._build()
        self._reload_targets()
        self.root.after(100, self._drain)

    # ---- layout ----
    def _build(self):
        top = ttk.Frame(self.root, padding=10)
        top.pack(fill="x")

        ttk.Label(top, text="Targets file:").grid(row=0, column=0, sticky="w")
        ttk.Entry(top, textvariable=self.targets_file, width=34).grid(row=0, column=1, sticky="w")
        ttk.Button(top, text="...", width=3, command=self._pick_file).grid(row=0, column=2, padx=(2, 12))
        ttk.Button(top, text="Reload", command=self._reload_targets).grid(row=0, column=3)

        ttk.Label(top, text="Target:").grid(row=1, column=0, sticky="w", pady=(8, 0))
        self.target_cb = ttk.Combobox(top, state="readonly", width=32)
        self.target_cb.grid(row=1, column=1, sticky="w", pady=(8, 0))
        ttk.Label(top, text="Iterations:").grid(row=1, column=2, sticky="e", pady=(8, 0))
        self.iters = tk.Spinbox(top, from_=1, to=20, width=5)
        self.iters.grid(row=1, column=3, sticky="w", pady=(8, 0))

        btns = ttk.Frame(self.root, padding=(10, 0))
        btns.pack(fill="x")
        self.test_btn = ttk.Button(btns, text="Test connection", command=self._on_test)
        self.test_btn.pack(side="left")
        self.run_btn = ttk.Button(btns, text="Run check (triggers IPL)", command=self._on_run)
        self.run_btn.pack(side="left", padx=6)
        self.report_btn = ttk.Button(btns, text="Save client report...",
                                     command=self._on_report, state="disabled")
        self.report_btn.pack(side="left")

        self.verdict_lbl = tk.Label(self.root, text="idle", anchor="w",
                                    font=("", 13, "bold"), fg="#fff", bg="#888",
                                    padx=10, pady=6)
        self.verdict_lbl.pack(fill="x", padx=10, pady=8)

        self.log = tk.Text(self.root, wrap="none", font=("Menlo", 11),
                           bg="#101418", fg="#d8dee9")
        self.log.pack(fill="both", expand=True, padx=10, pady=(0, 10))

    # ---- helpers ----
    def _pick_file(self):
        p = filedialog.askopenfilename(filetypes=[("YAML", "*.yaml *.yml"), ("all", "*")])
        if p:
            self.targets_file.set(p)
            self._reload_targets()

    def _reload_targets(self):
        names = engine.list_targets(Path(self.targets_file.get()))
        self.target_cb["values"] = names
        if names:
            self.target_cb.current(0)

    def _say(self, line: str):
        self.log.insert("end", line + "\n")
        self.log.see("end")

    def _set_verdict(self, code: str, sev: str, text: str):
        self.verdict_lbl.config(text=f"{code}  -  {text}", bg=SEV_COLOR.get(sev, "#888"))

    def _busy(self, on: bool):
        state = "disabled" if on else "normal"
        self.run_btn.config(state=state)
        self.test_btn.config(state=state)

    def _params(self):
        return {"target": self.target_cb.get(), "workers": 6, "interval": 0.5,
                "max_seconds": 900, "settle_seconds": 20, "log_source": None}

    def _load_target(self):
        return engine.load_target(Path(self.targets_file.get()), self.target_cb.get())

    # ---- actions ----
    def _on_test(self):
        try:
            t = self._load_target()
        except SystemExit as e:
            messagebox.showerror("Config", str(e))
            return
        self._busy(True)
        self._say("--- test connection ---")
        self._spawn(engine.dry_run(t, self._params(), self._emit))

    def _on_run(self):
        if not self.target_cb.get():
            return
        if not messagebox.askokcancel(
                "Confirm",
                "This triggers a real IPL of the selected LPAR. Continue?"):
            return
        try:
            t = self._load_target()
        except SystemExit as e:
            messagebox.showerror("Config", str(e))
            return
        n = int(self.iters.get())
        self.reports = []
        self._busy(True)
        self.report_btn.config(state="disabled")
        self._say(f"--- run: {n} iteration(s) ---")
        self._spawn(self._run_all(t, n))

    async def _run_all(self, t, n):
        for i in range(1, n + 1):
            self._emit("phase", {"phase": f"iteration {i}/{n}"})
            rep = await engine.run_once(t, i, self._params(), self._emit)
            engine.write_json(rep, Path("out"))
            self.reports.append(rep)

    def _on_report(self):
        if not self.reports:
            return
        default = f"client-report-{self.reports[0]['target']}.html"
        p = filedialog.asksaveasfilename(defaultextension=".html", initialfile=default,
                                         filetypes=[("HTML", "*.html")])
        if not p:
            return
        Path(p).write_text(report_mod.build_client_report(self.reports))
        messagebox.showinfo("Saved", f"Client report written:\n{p}")

    # ---- threading / event pump ----
    def _spawn(self, coro):
        def runner():
            try:
                asyncio.run(coro)
            except SystemExit as e:
                self.q.put(("phase", {"phase": f"error: {e}"}))
            except Exception as e:  # noqa: BLE001
                self.q.put(("phase", {"phase": f"error: {e!r}"}))
            finally:
                self.q.put(("__done__", {}))

        threading.Thread(target=runner, daemon=True).start()

    def _emit(self, kind, payload):
        self.q.put((kind, payload))

    def _drain(self):
        try:
            while True:
                kind, payload = self.q.get_nowait()
                self._handle(kind, payload)
        except queue.Empty:
            pass
        self.root.after(100, self._drain)

    def _handle(self, kind, payload):
        if kind == "log":
            self._say(f"  {payload['text'][:160]}")
        elif kind == "marker":
            self._say(f">> MARKER {payload['name']}")
        elif kind == "probe":
            self._say(f"   probe {payload['cell']:<14} {payload['outcome']}")
        elif kind == "phase":
            self._say(f"* {payload['phase']}")
        elif kind == "verdict":
            self._set_verdict(payload["code"], payload["severity"], payload["explanation"])
        elif kind == "__done__":
            self._busy(False)
            if self.reports:
                self.report_btn.config(state="normal")
            self._say("--- done ---")


def main():
    root = tk.Tk()
    App(root)
    root.mainloop()


if __name__ == "__main__":
    main()
