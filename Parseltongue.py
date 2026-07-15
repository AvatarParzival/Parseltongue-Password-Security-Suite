import hashlib
import math
import os
import secrets
import string
import sys
import threading
import urllib.request
import tkinter as tk
from tkinter import ttk


def resource_path(rel):
    """Resolve a bundled resource path (works both in dev and inside a
    PyInstaller one-file .exe, which unpacks data to sys._MEIPASS)."""
    base = getattr(sys, "_MEIPASS", os.path.dirname(os.path.abspath(__file__)))
    return os.path.join(base, rel)

BG = "#0d1117"       
CARD = "#161b22"      
FG = "#e6edf3"        
MUTED = "#8b949e"     
ACCENT = "#2f81f7"
GREEN = "#3fb950"
YELLOW = "#d29922"
ORANGE = "#db6d28"
RED = "#f85149"
CYAN = "#39c5cf"

FONT = ("Segoe UI", 10)
FONT_BOLD = ("Segoe UI", 10, "bold")
FONT_TITLE = ("Segoe UI", 16, "bold")
FONT_MONO = ("Consolas", 13, "bold")

COMMON_PASSWORDS = {"123456", "123456789", "password", "qwerty", "abc123", "111111", "welcome", "admin"}

def calculate_entropy(pw):
    pool = sum([26 if any(c.islower() for c in pw) else 0,
                26 if any(c.isupper() for c in pw) else 0,
                10 if any(c.isdigit() for c in pw) else 0,
                32 if any(c in string.punctuation for c in pw) else 0])
    return round(len(pw) * math.log2(pool), 2) if pool else 0.0


def has_repeated(pw):
    return any(pw[i] == pw[i + 1] == pw[i + 2] for i in range(len(pw) - 2))


def _has_seq(pw, sequences):
    pw_lower = pw.lower()
    return any(s[i:i + 4] in pw_lower or s[i:i + 4][::-1] in pw_lower
               for s in sequences for i in range(len(s) - 3))


def has_sequence(pw):
    return _has_seq(pw, ["abcdefghijklmnopqrstuvwxyz", "0123456789"])


def has_keyboard(pw):
    return _has_seq(pw, ["qwertyuiop", "asdfghjkl", "zxcvbnm", "1234567890"])


def check_hibp(pw):
    sha = hashlib.sha1(pw.encode()).hexdigest().upper()
    try:
        req = urllib.request.Request(
            "https://api.pwnedpasswords.com/range/" + sha[:5],
            headers={"User-Agent": "ParseltonguePwCheck"},
        )
        with urllib.request.urlopen(req, timeout=4) as r:
            for line in r.read().decode().splitlines():
                suffix, count = line.split(":")
                if suffix == sha[5:]:
                    return int(count)
    except Exception:
        return -1
    return 0


def evaluate(pw, run_breach_check=True):
    length = len(pw)
    has_upper = any(c.isupper() for c in pw)
    has_lower = any(c.islower() for c in pw)
    has_digit = any(c.isdigit() for c in pw)
    has_symbol = any(c in string.punctuation for c in pw)
    is_common = pw.lower() in COMMON_PASSWORDS

    rep = has_repeated(pw)
    seq = has_sequence(pw)
    kbd = has_keyboard(pw)
    entropy = calculate_entropy(pw)

    score = sum([
        3 if length >= 16 else (2 if length >= 12 else (1 if length >= 8 else 0)),
        has_upper, has_lower, has_digit, has_symbol,
        3 if entropy >= 80 else (2 if entropy >= 60 else (1 if entropy >= 40 else 0)),
        -rep, -seq, -kbd,
    ])
    score = max(0, min(10, score))

    feedback = []
    if is_common:
        score = 0
        feedback.append("CRITICAL: Common weak password.")

    pwned = check_hibp(pw) if run_breach_check else -1
    if pwned > 0:
        score = min(2, score)
        feedback.append(f"CRITICAL: Exposed in {pwned:,} known data breaches (Have I Been Pwned). Do NOT use it.")

    if length < 12:
        feedback.append("Increase length to 12+ characters for robust strength.")
    if not has_upper:
        feedback.append("Add uppercase letters (A-Z).")
    if not has_lower:
        feedback.append("Add lowercase letters (a-z).")
    if not has_digit:
        feedback.append("Add numbers (0-9).")
    if not has_symbol:
        feedback.append("Add special characters (e.g., @, #, $, %).")
    if rep:
        feedback.append("Avoid 3+ repeated characters (e.g., 'aaaa').")
    if seq:
        feedback.append("Avoid sequential strings (e.g., 'abcd', '1234').")
    if kbd:
        feedback.append("Avoid keyboard patterns (e.g., 'qwerty', 'asdf').")

    rating = ("Very Weak" if score <= 2 else "Weak" if score <= 4 else
              "Medium" if score <= 6 else "Strong" if score <= 8 else "Very Strong")

    entropy_quality = ("Very Strong entropy" if entropy >= 80 else
                       "Strong entropy" if entropy >= 60 else
                       "Moderate entropy" if entropy >= 40 else "Low entropy")

    return {
        "score": score, "rating": rating, "entropy": entropy, "feedback": feedback,
        "hibp_count": pwned, "entropy_quality": entropy_quality,
        "details": {
            "Has lowercase characters": has_lower,
            "Has uppercase characters": has_upper,
            "Has numbers": has_digit,
            "Has special characters": has_symbol,
            "Safe from common lists": not is_common,
            "No repeated characters": not rep,
            "No sequential characters": not seq,
            "No keyboard patterns": not kbd,
        },
    }


def generate_password(length=16, use_upper=True, use_lower=True, use_digits=True,
                      use_symbols=True, exclude_ambiguous=False):
    pool = ""
    if use_upper:
        pool += string.ascii_uppercase
    if use_lower:
        pool += string.ascii_lowercase
    if use_digits:
        pool += string.digits
    if use_symbols:
        pool += string.punctuation
    if exclude_ambiguous:
        pool = "".join(c for c in pool if c not in "lI1oO0|")
    if not pool:
        raise ValueError("No character pool selected.")
    return "".join(secrets.choice(pool) for _ in range(length))


def score_color(score):
    return (RED if score <= 2 else ORANGE if score <= 4 else
            YELLOW if score <= 6 else GREEN if score <= 8 else CYAN)


class PasswordSuiteApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Parseltongue Password Security Suite")
        self.geometry("760x680")
        self.minsize(680, 620)
        self.configure(bg=BG)

        self._set_window_icon()
        self._setup_style()
        self._build_header()

        self.notebook = ttk.Notebook(self)
        self.notebook.pack(fill="both", expand=True, padx=16, pady=(0, 8))

        self.check_tab = tk.Frame(self.notebook, bg=BG)
        self.gen_tab = tk.Frame(self.notebook, bg=BG)
        self.about_tab = tk.Frame(self.notebook, bg=BG)
        self.notebook.add(self.check_tab, text="  Check Strength  ")
        self.notebook.add(self.gen_tab, text="  Generate  ")
        self.notebook.add(self.about_tab, text="  About  ")

        self._build_check_tab()
        self._build_generate_tab()
        self._build_about_tab()

        self.after(60, self._apply_dark_titlebar)

    def _set_window_icon(self):
        if sys.platform == "win32":
            try:
                import ctypes
                ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID(
                    "vortextech.parseltongue.passwordsuite")
            except Exception:
                pass
        for name in ("snake.ico", "snake.png"):
            path = resource_path(name)
            if not os.path.exists(path):
                continue
            try:
                if name.endswith(".ico"):
                    self.iconbitmap(path)
                else:
                    self._icon_img = tk.PhotoImage(file=path)
                    self.iconphoto(True, self._icon_img)
                break
            except Exception:
                continue

    def _apply_dark_titlebar(self):
        """Turn the Windows title bar black (Windows 10 2004+/Windows 11)."""
        if sys.platform != "win32":
            return
        try:
            import ctypes
            self.update_idletasks()
            hwnd = ctypes.windll.user32.GetParent(self.winfo_id())
            value = ctypes.c_int(1)
            # 20 = modern flag; 19 = older Win10 builds. Try both.
            for attr in (20, 19):
                ctypes.windll.dwmapi.DwmSetWindowAttribute(
                    hwnd, attr, ctypes.byref(value), ctypes.sizeof(value))

            w, h = self.winfo_width(), self.winfo_height()
            self.geometry(f"{w + 1}x{h}")
            self.geometry(f"{w}x{h}")
        except Exception:
            pass

    def _setup_style(self):
        style = ttk.Style(self)
        try:
            style.theme_use("clam")
        except tk.TclError:
            pass
        style.configure("TNotebook", background=BG, borderwidth=0)
        style.configure("TNotebook.Tab", background=CARD, foreground=MUTED,
                        padding=(18, 10), font=FONT_BOLD, borderwidth=0)
        style.map("TNotebook.Tab",
                  background=[("selected", BG)],
                  foreground=[("selected", ACCENT)])
        style.configure("Strength.Horizontal.TProgressbar",
                        troughcolor=CARD, bordercolor=CARD, thickness=18)
        style.configure("TCombobox", fieldbackground=CARD, background=CARD)

    def _build_header(self):
        header = tk.Frame(self, bg=BG)
        header.pack(fill="x", padx=16, pady=(14, 8))
        tk.Label(header, text="PARSELTONGUE PASSWORD SECURITY SUITE",
                 bg=BG, fg=FG, font=FONT_TITLE).pack(anchor="w")
        tk.Label(header, text="Analyze password strength  \u2022  Generate secure passwords",
                 bg=BG, fg=MUTED, font=FONT).pack(anchor="w")
        tk.Frame(self, bg=ACCENT, height=2).pack(fill="x", padx=16)

    def _card(self, parent):
        return tk.Frame(parent, bg=CARD, highlightbackground="#30363d",
                        highlightthickness=1)

    def _build_check_tab(self):
        pad = {"padx": 14, "pady": 8}
        top = self._card(self.check_tab)
        top.pack(fill="x", **pad)

        tk.Label(top, text="Enter a password to analyze", bg=CARD, fg=FG,
                 font=FONT_BOLD).grid(row=0, column=0, columnspan=3, sticky="w", padx=12, pady=(12, 4))

        self.check_var = tk.StringVar()
        self.check_entry = tk.Entry(top, textvariable=self.check_var, show="\u2022",
                                    bg=BG, fg=FG, insertbackground=FG, font=FONT_MONO,
                                    relief="flat", width=40)
        self.check_entry.grid(row=1, column=0, sticky="we", padx=(12, 6), pady=(0, 12), ipady=6)
        self.check_entry.bind("<Return>", lambda e: self.on_analyze())

        self.show_var = tk.BooleanVar(value=False)
        tk.Checkbutton(top, text="Show", variable=self.show_var, command=self._toggle_show,
                       bg=CARD, fg=MUTED, selectcolor=CARD, activebackground=CARD,
                       activeforeground=FG, font=FONT, borderwidth=0,
                       highlightthickness=0).grid(row=1, column=1, padx=6, pady=(0, 12))

        tk.Button(top, text="Analyze", command=self.on_analyze, bg=ACCENT, fg="white",
                  activebackground="#1f6feb", activeforeground="white", font=FONT_BOLD,
                  relief="flat", padx=20, pady=6, cursor="hand2").grid(row=1, column=2, padx=(6, 12), pady=(0, 12))
        top.columnconfigure(0, weight=1)

        res = self._card(self.check_tab)
        res.pack(fill="both", expand=True, **pad)

        self.rating_lbl = tk.Label(res, text="Awaiting input\u2026", bg=CARD, fg=MUTED,
                                   font=("Segoe UI", 20, "bold"))
        self.rating_lbl.pack(anchor="w", padx=14, pady=(12, 2))

        bar_row = tk.Frame(res, bg=CARD)
        bar_row.pack(fill="x", padx=14, pady=(0, 8))
        self.score_bar = ttk.Progressbar(bar_row, style="Strength.Horizontal.TProgressbar",
                                         maximum=10, length=420)
        self.score_bar.pack(side="left", fill="x", expand=True)
        self.score_lbl = tk.Label(bar_row, text="0/10", bg=CARD, fg=FG, font=FONT_BOLD, width=6)
        self.score_lbl.pack(side="left", padx=8)

        self.meta_lbl = tk.Label(res, text="", bg=CARD, fg=FG, font=FONT, justify="left", anchor="w")
        self.meta_lbl.pack(fill="x", padx=14, pady=(0, 4))
        self.breach_lbl = tk.Label(res, text="", bg=CARD, fg=MUTED, font=FONT_BOLD, anchor="w")
        self.breach_lbl.pack(fill="x", padx=14, pady=(0, 8))

        body = tk.Frame(res, bg=CARD)
        body.pack(fill="both", expand=True, padx=14, pady=(0, 12))

        left = tk.Frame(body, bg=CARD)
        left.pack(side="left", fill="both", expand=True)
        tk.Label(left, text="Checklist", bg=CARD, fg=ACCENT, font=FONT_BOLD).pack(anchor="w")
        self.checklist_frame = tk.Frame(left, bg=CARD)
        self.checklist_frame.pack(anchor="w", fill="x", pady=4)

        right = tk.Frame(body, bg=CARD)
        right.pack(side="left", fill="both", expand=True, padx=(12, 0))
        tk.Label(right, text="Recommendations", bg=CARD, fg=ACCENT, font=FONT_BOLD).pack(anchor="w")
        self.rec_frame = tk.Frame(right, bg=CARD)
        self.rec_frame.pack(anchor="w", fill="x", pady=4)

    def _toggle_show(self):
        self.check_entry.config(show="" if self.show_var.get() else "\u2022")

    def on_analyze(self):
        pw = self.check_var.get()
        if not pw:
            self.rating_lbl.config(text="Enter a password first", fg=MUTED)
            return
        self.rating_lbl.config(text="Analyzing\u2026", fg=MUTED)
        self.breach_lbl.config(text="Checking breach database\u2026", fg=MUTED)
        self.update_idletasks()

        threading.Thread(target=self._analyze_worker, args=(pw,), daemon=True).start()

    def _analyze_worker(self, pw):
        res = evaluate(pw, run_breach_check=True)
        self.after(0, lambda: self._render_results(res))

    def _render_results(self, res):
        color = score_color(res["score"])
        self.rating_lbl.config(text=res["rating"], fg=color)
        self.score_bar["value"] = res["score"]
        self.score_lbl.config(text=f"{res['score']}/10", fg=color)
        self.meta_lbl.config(
            text=f"Entropy: {res['entropy']} bits   ({res['entropy_quality']})")

        pwned = res["hibp_count"]
        if pwned > 0:
            self.breach_lbl.config(text=f"BREACH: found in {pwned:,} known breaches!", fg=RED)
        elif pwned == 0:
            self.breach_lbl.config(text="Not found in any known breaches.", fg=GREEN)
        else:
            self.breach_lbl.config(text="Breach check unavailable (offline).", fg=MUTED)

        for w in self.checklist_frame.winfo_children():
            w.destroy()
        for label, ok in res["details"].items():
            mark = "\u2714" if ok else "\u2718"
            tk.Label(self.checklist_frame,
                     text=mark + "  " + label,
                     bg=CARD, fg=(GREEN if ok else RED), font=FONT,
                     anchor="w").pack(anchor="w")

        for w in self.rec_frame.winfo_children():
            w.destroy()
        if res["feedback"]:
            for fb in res["feedback"]:
                col = RED if "CRITICAL" in fb else YELLOW
                tk.Label(self.rec_frame, text=f"\u2022 {fb}", bg=CARD, fg=col,
                         font=FONT, wraplength=300, justify="left",
                         anchor="w").pack(anchor="w", pady=1)
        else:
            tk.Label(self.rec_frame, text="\u2714 Excellent password!", bg=CARD,
                     fg=GREEN, font=FONT_BOLD, anchor="w").pack(anchor="w")
            
    def _build_generate_tab(self):
        pad = {"padx": 14, "pady": 8}
        opts = self._card(self.gen_tab)
        opts.pack(fill="x", **pad)

        tk.Label(opts, text="Password length", bg=CARD, fg=FG,
                 font=FONT_BOLD).grid(row=0, column=0, sticky="w", padx=12, pady=(12, 2))
        self.len_var = tk.IntVar(value=16)
        self.len_spin = tk.Spinbox(
            opts, from_=8, to=128, textvariable=self.len_var, width=5,
            font=FONT_BOLD, justify="center", bg=BG, fg=CYAN,
            buttonbackground=CARD, relief="flat", insertbackground=CYAN,
            highlightthickness=1, highlightbackground="#30363d", highlightcolor=ACCENT)
        self.len_spin.grid(row=0, column=1, sticky="e", padx=12)
        self.len_spin.bind("<FocusOut>", lambda e: self._clamp_length())
        self.len_spin.bind("<Return>", lambda e: self._clamp_length())
        scale = tk.Scale(opts, from_=8, to=128, orient="horizontal", variable=self.len_var,
                         bg=CARD, fg=FG, troughcolor=BG, highlightthickness=0,
                         showvalue=False)
        scale.grid(row=1, column=0, columnspan=2, sticky="we", padx=12, pady=(0, 8))

        self.opt_upper = tk.BooleanVar(value=True)
        self.opt_lower = tk.BooleanVar(value=True)
        self.opt_digits = tk.BooleanVar(value=True)
        self.opt_symbols = tk.BooleanVar(value=True)
        self.opt_ambig = tk.BooleanVar(value=False)
        checks = [
            ("Uppercase (A-Z)", self.opt_upper),
            ("Lowercase (a-z)", self.opt_lower),
            ("Digits (0-9)", self.opt_digits),
            ("Symbols (!@#$)", self.opt_symbols),
            ("Exclude ambiguous (l I 1 o O 0 |)", self.opt_ambig),
        ]
        cf = tk.Frame(opts, bg=CARD)
        cf.grid(row=2, column=0, columnspan=2, sticky="w", padx=12, pady=(0, 8))
        for i, (label, var) in enumerate(checks):
            tk.Checkbutton(cf, text=label, variable=var, bg=CARD, fg=FG, selectcolor=BG,
                           activebackground=CARD, activeforeground=FG, font=FONT,
                           borderwidth=0, highlightthickness=0,
                           anchor="w").grid(row=i // 2, column=i % 2, sticky="w", padx=4, pady=2)

        tk.Button(opts, text="Generate Password", command=self.on_generate, bg=GREEN,
                  fg="#08210f", activebackground="#2ea043", activeforeground="white",
                  font=FONT_BOLD, relief="flat", padx=20, pady=8,
                  cursor="hand2").grid(row=3, column=0, columnspan=2, sticky="we", padx=12, pady=(4, 12))
        opts.columnconfigure(0, weight=1)

        out = self._card(self.gen_tab)
        out.pack(fill="x", **pad)
        tk.Label(out, text="Generated password", bg=CARD, fg=ACCENT,
                 font=FONT_BOLD).pack(anchor="w", padx=12, pady=(12, 4))
        row = tk.Frame(out, bg=CARD)
        row.pack(fill="x", padx=12, pady=(0, 12))
        self.gen_var = tk.StringVar()
        gen_entry = tk.Entry(row, textvariable=self.gen_var, bg=BG, fg=CYAN,
                             font=FONT_MONO, relief="flat", readonlybackground=BG,
                             state="readonly")
        gen_entry.pack(side="left", fill="x", expand=True, ipady=6, padx=(0, 6))
        tk.Button(row, text="Copy", command=self.on_copy, bg=ACCENT, fg="white",
                  activebackground="#1f6feb", activeforeground="white", font=FONT_BOLD,
                  relief="flat", padx=16, pady=4, cursor="hand2").pack(side="left")

        self.gen_summary = tk.Label(out, text="", bg=CARD, fg=MUTED, font=FONT, anchor="w")
        self.gen_summary.pack(fill="x", padx=12, pady=(0, 12))

    def _clamp_length(self):
        """Keep the typed length within 8-128 and reflect it in the UI."""
        try:
            n = int(self.len_var.get())
        except Exception:
            n = 16
        n = max(8, min(128, n))
        self.len_var.set(n)
        return n

    def on_generate(self):
        try:
            pw = generate_password(
                length=self._clamp_length(),
                use_upper=self.opt_upper.get(),
                use_lower=self.opt_lower.get(),
                use_digits=self.opt_digits.get(),
                use_symbols=self.opt_symbols.get(),
                exclude_ambiguous=self.opt_ambig.get(),
            )
        except ValueError as e:
            self.gen_var.set("")
            self.gen_summary.config(text=f"Error: {e}", fg=RED)
            return
        self.gen_var.set(pw)
        res = evaluate(pw, run_breach_check=False)
        c = score_color(res["score"])
        self.gen_summary.config(
            text=f"Strength: {res['rating']}   |   Score: {res['score']}/10   |   Entropy: {res['entropy']} bits",
            fg=c)

    def on_copy(self):
        pw = self.gen_var.get()
        if pw:
            self.clipboard_clear()
            self.clipboard_append(pw)
            self.gen_summary.config(text="Copied to clipboard!", fg=GREEN)

    def _build_about_tab(self):
        card = self._card(self.about_tab)
        card.pack(fill="both", expand=True, padx=14, pady=8)
        about = (
            "Parseltongue Password Security Suite\n\n"
            "A local tool for analyzing password strength and generating\n"
            "cryptographically secure passwords.\n\n"
            "Features:\n"
            "  \u2022 Entropy calculation and strength scoring (0-10)\n"
            "  \u2022 Checks for repeated, sequential, and keyboard patterns\n"
            "  \u2022 Common-password detection\n"
            "  \u2022 Have I Been Pwned breach lookup (needs internet)\n"
            "  \u2022 Secure generator using Python's secrets module\n\n"
            "Privacy: breach checks use the k-anonymity range API \u2014 only the\n"
            "first 5 characters of the SHA-1 hash ever leave your machine.\n\n"
            "Abdullah Zubair \u2022 CyberSec Portfolio\n"
            "Email: abdullah69zubair@gmail.com\n"
            "LinkedIn: Linkedin.com/in/abdullahzubairr\n"
            "GitHub: github.com/AvatarParzival"
        )
        tk.Label(card, text=about, bg=CARD, fg=FG, font=FONT, justify="left",
                 anchor="nw").pack(fill="both", expand=True, padx=16, pady=16)


if __name__ == "__main__":
    app = PasswordSuiteApp()
    app.mainloop()