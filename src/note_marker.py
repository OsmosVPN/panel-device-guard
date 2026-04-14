"""Helpers for reading/writing guard markers embedded in user notes."""


def extract_guard_meta(note: str | None, prefix: str) -> dict[str, str] | None:
    if not note:
        return None
    for part in note.splitlines():
        part = part.strip()
        if not part.startswith(prefix):
            continue
        out = dict(chunk.split("=", 1) for chunk in part.split()[1:] if "=" in chunk)
        if "until" in out:
            return out
    return None


def remove_guard_marker(note: str | None, prefix: str) -> str:
    if not note:
        return ""
    return "\n".join(ln for ln in note.splitlines() if not ln.strip().startswith(prefix)).strip()


def append_guard_marker(note: str | None, prefix: str, until_iso: str, prev_status: str) -> str:
    clean = remove_guard_marker(note, prefix)
    marker = f"{prefix} until={until_iso} prev={prev_status}"
    return (f"{clean}\n{marker}" if clean else marker)[:500]
