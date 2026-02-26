import tkinter as tk
from tkinter import ttk

class PasswordEntry(tk.Frame):
    def __init__(self, master, **kwargs):
        super().__init__(master)
        self.is_visible = False

        self.entry = tk.Entry(self, show="*", **kwargs)
        self.entry.pack(side=tk.LEFT, fill=tk.X, expand=True)

        self.toggle_btn = tk.Button(self, text="👁", command=self.toggle, width=2)
        self.toggle_btn.pack(side=tk.RIGHT)

    def toggle(self):
        self.is_visible = not self.is_visible
        self.entry.config(show="" if self.is_visible else "*")

    def get(self): return self.entry.get()