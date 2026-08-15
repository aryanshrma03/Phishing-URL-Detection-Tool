import customtkinter as ctk

class ResultsPanel:
    def __init__(self, parent):
        self.frame = ctk.CTkFrame(parent, corner_radius=14)
        self.frame.pack(fill="both", expand=True, padx=30, pady=8)

        columns = ctk.CTkFrame(self.frame, fg_color="transparent")
        columns.pack(fill="both", expand=True, padx=15, pady=15)

        left = ctk.CTkFrame(columns, corner_radius=10)
        left.pack(side="left", fill="both", expand=True, padx=(0, 6))

        right = ctk.CTkFrame(columns, corner_radius=10)
        right.pack(side="right", fill="both", expand=True, padx=(6, 0))

        ctk.CTkLabel(
            left, text="Security Findings",
            font=("Segoe UI", 14, "bold")
        ).pack(anchor="w", padx=15, pady=(12, 5))

        ctk.CTkLabel(
            right, text="Recommendations",
            font=("Segoe UI", 14, "bold")
        ).pack(anchor="w", padx=15, pady=(12, 5))

        self.findings = ctk.CTkTextbox(left, height=220)
        self.findings.pack(fill="both", expand=True, padx=10, pady=(0, 10))

        self.recommendations = ctk.CTkTextbox(right, height=220)
        self.recommendations.pack(fill="both", expand=True, padx=10, pady=(0, 10))

    def update(self, risk):
        self.findings.configure(state="normal")
        self.findings.delete("1.0", "end")

        if not risk.findings:
            self.findings.insert("end", "✓ No heuristic warnings detected.\n")
        else:
            for finding in risk.findings:
                self.findings.insert(
                    "end",
                    f"[{finding['severity']}] {finding['name']}\n"
                    f"    {finding['reason']}\n\n",
                )

        self.findings.configure(state="disabled")

        self.recommendations.configure(state="normal")
        self.recommendations.delete("1.0", "end")

        for recommendation in risk.recommendations:
            self.recommendations.insert("end", f"• {recommendation}\n\n")

        self.recommendations.configure(state="disabled")
