import customtkinter as ctk

class RiskMeter:
    def __init__(self, parent):
        self.frame = ctk.CTkFrame(parent, corner_radius=14)
        self.frame.pack(fill="x", padx=30, pady=10)

        header = ctk.CTkFrame(self.frame, fg_color="transparent")
        header.pack(fill="x", padx=18, pady=(14, 5))

        self.label = ctk.CTkLabel(
            header,
            text="Awaiting analysis",
            font=("Segoe UI", 16, "bold"),
        )
        self.label.pack(side="left")

        self.score = ctk.CTkLabel(
            header,
            text="0 / 100",
            font=("Segoe UI", 16, "bold"),
        )
        self.score.pack(side="right")

        self.progress = ctk.CTkProgressBar(self.frame, height=14, corner_radius=7)
        self.progress.pack(fill="x", padx=18, pady=(4, 16))
        self.progress.set(0)

    def update(self, score, label):
        self.label.configure(text=label)
        self.score.configure(text=f"{score} / 100")
        self.progress.set(score / 100)
