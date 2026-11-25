"""Run with xvfb-run on a Linux CI worker with python3-tk."""
import tkinter as tk
from tkinter import ttk
from unittest.mock import patch
from systemsentinel.gui import main

root = tk.Tk()
result = {"passed": False}


def descendants(widget):
    for child in widget.winfo_children():
        yield child
        yield from descendants(child)


def start():
    buttons = [w for w in descendants(root) if isinstance(w, ttk.Button) and w.cget("text") == "Start scan"]
    if len(buttons) != 1:
        root.destroy()
        return
    config = [w for w in descendants(root) if isinstance(w, ttk.Checkbutton)
              and w.cget("text") == "Review basic system file permissions"]
    if len(config) != 1:
        root.destroy()
        return
    config[0].invoke()
    buttons[0].invoke()


def check():
    positions = [w for w in descendants(root) if isinstance(w, ttk.Treeview)]
    if len(positions) == 4 and positions[0].get_children() and len(positions[3].get_children()) == 6:
        result["passed"] = True
        root.destroy()
    else:
        root.after(100, check)

root.after(100, start)
root.after(200, check)
root.after(15000, root.destroy)
with patch("tkinter.Tk", return_value=root):
    main()
if not result["passed"]:
    raise SystemExit("GUI smoke test did not observe inventory rows")
print("GUI smoke test passed")
