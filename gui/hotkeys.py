"""Clipboard and standard hotkeys for CustomTkinter on Windows.

CTkEntry / CTkTextbox often ignore Ctrl+C/V/X/A. With a Russian layout the
letter keysyms become Cyrillic, so we bind by physical keycode instead.
"""

from __future__ import annotations

import sys
import tkinter as tk

import customtkinter as ctk

# Windows virtual-key codes (layout-independent)
_VK = {
    "a": 65,
    "c": 67,
    "v": 86,
    "x": 88,
    "z": 90,
}


def _inner(widget: tk.Misc) -> tk.Misc:
    if isinstance(widget, ctk.CTkEntry):
        return widget._entry  # noqa: SLF001
    if isinstance(widget, ctk.CTkTextbox):
        return widget._textbox  # noqa: SLF001
    return widget


def _clipboard_get(widget: tk.Misc) -> str:
    try:
        return widget.clipboard_get()
    except tk.TclError:
        return ""


def _is_ctrl(event) -> bool:
    # 0x4 = Control, 0x20000 sometimes appears on Windows
    return bool(event.state & 0x4) or bool(getattr(event, "state", 0) & 0x20000)


def _match_key(event, name: str) -> bool:
    """Match physical key even when OS layout is Russian."""
    keysym = (event.keysym or "").lower()
    char = (event.char or "").lower()
    if keysym == name or char == name:
        return True
    if sys.platform == "win32" and getattr(event, "keycode", None) == _VK[name]:
        return True
    return False


def enable_entry_hotkeys(entry: ctk.CTkEntry) -> ctk.CTkEntry:
    inner = _inner(entry)

    def copy(_event=None):
        try:
            text = inner.selection_get()
        except tk.TclError:
            return "break"
        entry.clipboard_clear()
        entry.clipboard_append(text)
        return "break"

    def cut(_event=None):
        copy()
        try:
            inner.delete("sel.first", "sel.last")
        except tk.TclError:
            pass
        return "break"

    def paste(_event=None):
        text = _clipboard_get(entry)
        if not text:
            return "break"
        try:
            inner.delete("sel.first", "sel.last")
        except tk.TclError:
            pass
        inner.insert("insert", text)
        return "break"

    def select_all(_event=None):
        inner.select_range(0, "end")
        inner.icursor("end")
        return "break"

    def undo(_event=None):
        try:
            inner.event_generate("<<Undo>>")
        except tk.TclError:
            pass
        return "break"

    def on_key(event):
        if not _is_ctrl(event):
            return None
        if _match_key(event, "c"):
            return copy()
        if _match_key(event, "x"):
            return cut()
        if _match_key(event, "v"):
            return paste()
        if _match_key(event, "a"):
            return select_all()
        if _match_key(event, "z"):
            return undo()
        return None

    # Bind Latin sequences + generic Key for RU layout
    for w in (entry, inner):
        w.bind("<Control-c>", copy)
        w.bind("<Control-C>", copy)
        w.bind("<Control-x>", cut)
        w.bind("<Control-X>", cut)
        w.bind("<Control-v>", paste)
        w.bind("<Control-V>", paste)
        w.bind("<Control-a>", select_all)
        w.bind("<Control-A>", select_all)
        w.bind("<Control-z>", undo)
        w.bind("<Control-Z>", undo)
        w.bind("<Control-KeyPress>", on_key)
        w.bind("<KeyPress>", on_key)

    menu = tk.Menu(entry, tearoff=0)
    menu.add_command(label="Вырезать", command=cut)
    menu.add_command(label="Копировать", command=copy)
    menu.add_command(label="Вставить", command=paste)
    menu.add_separator()
    menu.add_command(label="Выделить всё", command=select_all)

    def popup(event):
        try:
            menu.tk_popup(event.x_root, event.y_root)
        finally:
            menu.grab_release()

    inner.bind("<Button-3>", popup)
    return entry


def enable_textbox_hotkeys(box: ctk.CTkTextbox) -> ctk.CTkTextbox:
    inner = _inner(box)

    def copy(_event=None):
        try:
            text = inner.get("sel.first", "sel.last")
        except tk.TclError:
            return "break"
        box.clipboard_clear()
        box.clipboard_append(text)
        return "break"

    def cut(_event=None):
        if str(inner.cget("state")) == "disabled":
            return copy()
        copy()
        try:
            inner.delete("sel.first", "sel.last")
        except tk.TclError:
            pass
        return "break"

    def paste(_event=None):
        if str(inner.cget("state")) == "disabled":
            return "break"
        text = _clipboard_get(box)
        if not text:
            return "break"
        try:
            inner.delete("sel.first", "sel.last")
        except tk.TclError:
            pass
        inner.insert("insert", text)
        return "break"

    def select_all(_event=None):
        inner.tag_add("sel", "1.0", "end-1c")
        inner.mark_set("insert", "end-1c")
        inner.see("insert")
        return "break"

    def undo(_event=None):
        try:
            inner.edit_undo()
        except tk.TclError:
            pass
        return "break"

    try:
        inner.configure(undo=True)
    except tk.TclError:
        pass

    def on_key(event):
        if not _is_ctrl(event):
            return None
        if _match_key(event, "c"):
            return copy()
        if _match_key(event, "x"):
            return cut()
        if _match_key(event, "v"):
            return paste()
        if _match_key(event, "a"):
            return select_all()
        if _match_key(event, "z"):
            return undo()
        return None

    for w in (box, inner):
        w.bind("<Control-c>", copy)
        w.bind("<Control-C>", copy)
        w.bind("<Control-x>", cut)
        w.bind("<Control-X>", cut)
        w.bind("<Control-v>", paste)
        w.bind("<Control-V>", paste)
        w.bind("<Control-a>", select_all)
        w.bind("<Control-A>", select_all)
        w.bind("<Control-z>", undo)
        w.bind("<Control-Z>", undo)
        w.bind("<Control-KeyPress>", on_key)
        w.bind("<KeyPress>", on_key)

    menu = tk.Menu(box, tearoff=0)
    menu.add_command(label="Вырезать", command=cut)
    menu.add_command(label="Копировать", command=copy)
    menu.add_command(label="Вставить", command=paste)
    menu.add_separator()
    menu.add_command(label="Выделить всё", command=select_all)

    def popup(event):
        try:
            menu.tk_popup(event.x_root, event.y_root)
        finally:
            menu.grab_release()

    inner.bind("<Button-3>", popup)
    return box
