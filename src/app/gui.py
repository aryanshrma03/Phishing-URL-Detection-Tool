import customtkinter as ctk
from tkinter import messagebox

from analyzer.heuristics import analyze_heuristics
from analyzer.scoring import calculate_risk
from analyzer.url_parser import parse_url
from analyzer.virustotal import VirusTotalError, lookup_url
from components.header import create_header
from components.risk_meter import RiskMeter
from components.results import ResultsPanel
from components.url_input import create_url_input
from config.theme import load_theme

load_theme()

class PhishingURLDetectionTool:
    def __init__(self):
        self.root = ctk.CTk()
        self.root.title("Phishing URL Detection Tool")
        self.root.geometry("980x760")
        self.root.minsize(850, 700)

        self.url_var = ctk.StringVar()

        create_header(self.root)
        self.entry = create_url_input(self.root, self.url_var, self.analyze)
        self.meter = RiskMeter(self.root)
        self.results = ResultsPanel(self.root)

        actions = ctk.CTkFrame(self.root, fg_color="transparent")
        actions.pack(fill="x", padx=30, pady=(2, 4))

        ctk.CTkButton(
            actions,
            text="VirusTotal Lookup",
            command=self.virustotal_lookup,
            width=180,
            height=40,
            corner_radius=10,
        ).pack(side="left")

        ctk.CTkButton(
            actions,
            text="Clear",
            command=self.clear,
            width=110,
            height=40,
            corner_radius=10,
            fg_color="#3b3f46",
            hover_color="#4b5058",
        ).pack(side="right")

        ctk.CTkLabel(
            self.root,
            text="⚠ Heuristic analysis is not proof of safety. Verify suspicious links independently.",
            text_color="#9aa4b2",
            font=("Segoe UI", 11),
        ).pack(anchor="w", padx=30, pady=(5, 18))

    def analyze(self):
        raw_url = self.url_var.get().strip()

        if not raw_url:
            messagebox.showwarning("URL Required", "Enter a URL to analyze.")
            return

        parsed = parse_url(raw_url)
        findings = analyze_heuristics(parsed)
        risk = calculate_risk(findings)

        self.meter.update(risk.score, risk.label)
        self.results.update(risk)

    def virustotal_lookup(self):
        raw_url = self.url_var.get().strip()

        if not raw_url:
            messagebox.showwarning("URL Required", "Enter a URL first.")
            return

        parsed = parse_url(raw_url)
        if not parsed.is_valid:
            messagebox.showerror("Invalid URL", "Enter a valid HTTP/HTTPS URL.")
            return

        try:
            data = lookup_url(parsed.normalized)
        except VirusTotalError as exc:
            messagebox.showerror(
                "VirusTotal Lookup",
                f"Lookup could not be completed.\n\n{exc}",
            )
            return

        if not data.get("data"):
            messagebox.showinfo(
                "VirusTotal",
                "No existing VirusTotal record was found for this URL.",
            )
            return

        attributes = data.get("data", {}).get("attributes", {})
        stats = attributes.get("last_analysis_stats", {})

        messagebox.showinfo(
            "VirusTotal Reputation",
            "Detection summary:\n\n"
            f"Malicious: {stats.get('malicious', 0)}\n"
            f"Suspicious: {stats.get('suspicious', 0)}\n"
            f"Undetected: {stats.get('undetected', 0)}\n"
            f"Harmless: {stats.get('harmless', 0)}",
        )

    def clear(self):
        self.url_var.set("")
        self.meter.update(0, "Awaiting analysis")
        self.results.update(calculate_risk([]))
        self.entry.focus_set()

    def run(self):
        self.root.mainloop()
