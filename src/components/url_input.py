import customtkinter as ctk

def create_url_input(parent, variable, on_scan):
    frame = ctk.CTkFrame(parent, fg_color="transparent")
    frame.pack(fill="x", padx=30, pady=(12, 8))

    entry = ctk.CTkEntry(
        frame,
        textvariable=variable,
        height=48,
        placeholder_text="https://example.com/login",
        font=("Segoe UI", 14),
        corner_radius=12,
    )
    entry.pack(side="left", fill="x", expand=True)
    entry.bind("<Return>", lambda _event: on_scan())

    button = ctk.CTkButton(
        frame,
        text="Analyze URL",
        command=on_scan,
        width=150,
        height=48,
        corner_radius=12,
        font=("Segoe UI", 13, "bold"),
    )
    button.pack(side="right", padx=(12, 0))

    return entry
