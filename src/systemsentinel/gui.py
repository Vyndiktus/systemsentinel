"""Optional Tk desktop interface, using the shared inventory and patch functions."""
import queue
import threading

from .inventory import detect_os, collect_packages
from .advisories import load_snapshot, patch_findings, release_covered
from .cache import read_cache
from .updates import collect_updates


def scan_local(path="", digest="", allow_synthetic=False, cached=False):
    os_info = detect_os()
    packages = collect_packages(os_info)
    metadata, findings = None, []
    if cached:
        snapshot, metadata = read_cache(allow_synthetic=allow_synthetic)
    elif path:
        snapshot, metadata = load_snapshot(path, digest or None, allow_synthetic)
    if metadata is not None:
        metadata["release_covered"] = release_covered(snapshot, os_info)
        findings = patch_findings(snapshot, os_info, packages)
    return os_info, packages, metadata, findings


def main():
    try:
        import tkinter as tk
        from tkinter import filedialog, ttk, messagebox
        root = tk.Tk()
    except (ImportError, RuntimeError) as exc:
        raise SystemExit(f"Desktop interface unavailable: {exc}. Use the CLI or install your distribution's Python Tk package.")
    except Exception as exc:
        raise SystemExit(f"Cannot open a desktop window: {exc}. Use the CLI on headless systems.")

    root.title("SystemSentinel | Linux security maintenance")
    root.geometry("980x650")
    root.minsize(720, 480)
    root.columnconfigure(0, weight=1)
    root.rowconfigure(2, weight=1)
    top = ttk.Frame(root, padding=16)
    top.grid(row=0, column=0, sticky="ew")
    top.columnconfigure(1, weight=1)
    ttk.Label(top, text="SystemSentinel", font=("TkDefaultFont", 20, "bold")).grid(row=0, column=0, columnspan=3, sticky="w")
    ttk.Label(top, text="Read-only package inventory and vendor patch guidance").grid(row=1, column=0, columnspan=3, sticky="w", pady=(0, 12))
    path = tk.StringVar()
    digest = tk.StringVar()
    synthetic = tk.BooleanVar()
    cached = tk.BooleanVar()
    apt_updates = tk.BooleanVar()
    ttk.Label(top, text="Advisory snapshot (optional)").grid(row=2, column=0, sticky="w", padx=(0, 10))
    ttk.Entry(top, textvariable=path).grid(row=2, column=1, sticky="ew")
    def browse():
        selected = filedialog.askopenfilename(filetypes=[("JSON snapshot", "*.json"), ("All files", "*")])
        if selected:
            path.set(selected)
    ttk.Button(top, text="Browse…", command=browse).grid(row=2, column=2, padx=(8, 0))
    ttk.Label(top, text="Trusted SHA-256 (optional)").grid(row=3, column=0, sticky="w", pady=6)
    ttk.Entry(top, textvariable=digest).grid(row=3, column=1, columnspan=2, sticky="ew")
    ttk.Checkbutton(top, text="Allow fictional test data", variable=synthetic).grid(row=4, column=1, sticky="w")
    ttk.Checkbutton(top, text="Use imported offline database", variable=cached).grid(row=5, column=1, sticky="w")
    ttk.Checkbutton(top, text="Check available APT updates (existing indexes)", variable=apt_updates).grid(row=6, column=1, sticky="w")
    status = tk.StringVar(value="Ready. Choose an optional snapshot, then start a scan.")
    summary = ttk.Label(root, textvariable=status, padding=(16, 6), wraplength=850)
    summary.grid(row=1, column=0, sticky="ew")

    tabs = ttk.Notebook(root)
    tabs.grid(row=2, column=0, sticky="nsew", padx=16, pady=(0, 8))
    def make_table(label, columns, widths):
        panel = ttk.Frame(tabs)
        tabs.add(panel, text=label)
        panel.rowconfigure(0, weight=1)
        panel.columnconfigure(0, weight=1)
        tree = ttk.Treeview(panel, columns=columns, show="headings")
        for column, width in zip(columns, widths):
            tree.heading(column, text=column)
            tree.column(column, width=width, minwidth=75)
        tree.grid(row=0, column=0, sticky="nsew")
        scroll = ttk.Scrollbar(panel, orient="vertical", command=tree.yview)
        scroll.grid(row=0, column=1, sticky="ns")
        tree.configure(yscrollcommand=scroll.set)
        horizontal = ttk.Scrollbar(panel, orient="horizontal", command=tree.xview)
        horizontal.grid(row=1, column=0, sticky="ew")
        tree.configure(xscrollcommand=horizontal.set)
        return tree

    inventory = make_table("Installed packages", ("Package", "Version", "Architecture"), (280, 380, 100))
    patch_table = make_table("Vendor patch guidance", ("Package", "Installed", "Fixed", "Advisory"), (220, 200, 200, 150))
    update_table = make_table("Available APT updates", ("Package", "Installed", "Candidate", "Source"), (220, 200, 200, 150))
    detail = tk.StringVar(value="Select a vendor finding to see its recommendation and reference.")
    ttk.Label(root, textvariable=detail, padding=(16, 4), wraplength=850).grid(row=3, column=0, sticky="ew")
    footer = ttk.Frame(root, padding=(16, 4, 16, 16))
    footer.grid(row=4, column=0, sticky="ew")
    results = queue.Queue()
    current_findings = {}

    def selection(_event):
        selected = patch_table.selection()
        if selected and selected[0] in current_findings:
            finding = current_findings[selected[0]]
            detail.set(f"{finding['recommendation']} Reference: {finding['reference']}")
    patch_table.bind("<<TreeviewSelect>>", selection)

    def poll():
        try:
            ok, result = results.get_nowait()
        except queue.Empty:
            root.after(100, poll)
            return
        scan_button.configure(state="normal")
        if not ok:
            status.set("Scan failed. No current results.")
            messagebox.showerror("Scan failed", str(result))
            return
        (os_info, packages, metadata, findings), updates = result
        for p in packages:
            inventory.insert("", "end", values=(p.name, p.version, p.architecture))
        for f in findings:
            key = patch_table.insert("", "end", values=(f["package"], f["installed_version"], f["fixed_version"], f["advisory"]))
            current_findings[key] = f
        base = f"{os_info['PRETTY_NAME']} | {len(packages)} installed packages. "
        if metadata is None:
            status.set(base + "Inventory only; no advisory database configured.")
        else:
            notes = ["FICTIONAL TEST DATA" if metadata["synthetic"] else "Local snapshot",
                     f"{metadata['age_days']} days old", f"{len(findings)} patch findings"]
            if not metadata["release_covered"]:
                notes.append("no records for this release")
            if metadata["stale"]:
                notes.append("STALE")
            if not metadata["digest_checked"]:
                notes.append("digest not verified")
            status.set(base + " • ".join(notes) + ". Findings are limited to snapshot coverage.")
            tabs.select(1)
        if updates is not None:
            for item in updates:
                update_table.insert("", "end", values=(item["package"], item["installed_version"], item["candidate_version"], "Security pocket" if item["security_pocket"] else "General/other"))
            status.set(status.get() + f" APT candidates: {len(updates)}; index freshness unknown.")
            tabs.select(2)

    def run():
        snapshot_path, expected_digest, allow = path.get().strip(), digest.get().strip(), synthetic.get()
        use_cache = cached.get()
        if use_cache and (snapshot_path or expected_digest):
            messagebox.showerror("Choose one database", "Clear the file and digest fields to use the imported offline database.")
            return
        if not snapshot_path and not use_cache and (expected_digest or allow):
            messagebox.showerror("Snapshot required", "Choose a snapshot before using its options.")
            return
        check_updates = apt_updates.get()
        for table in (inventory, patch_table, update_table):
            children = table.get_children()
            if children:
                table.delete(*children)
        current_findings.clear()
        detail.set("Select a vendor finding to see its recommendation and reference.")
        scan_button.configure(state="disabled")
        status.set("Scanning local package information…")
        def worker():
            try:
                results.put((True, (scan_local(snapshot_path, expected_digest, allow, use_cache), collect_updates() if check_updates else None)))
            except Exception as exc:
                results.put((False, exc))
        threading.Thread(target=worker, daemon=True).start()
        root.after(100, poll)
    scan_button = ttk.Button(footer, text="Start scan", command=run)
    scan_button.pack(side="left")
    ttk.Label(footer, text="This application never installs updates or changes system settings.").pack(side="left", padx=12)
    root.mainloop()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
