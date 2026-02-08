from __future__ import annotations
import platform
import subprocess
import csv
import shlex
import socket
from typing import Dict, Iterator, Optional

def hostname() -> str:
    return socket.gethostname()

def list_processes() -> Iterator[Dict[str, Optional[str]]]:
    if platform.system().lower().startswith("win"):
        try:
            cmd = ["wmic", "process", "get", "ProcessId,Name,CommandLine"]
            out = subprocess.check_output(cmd, stderr=subprocess.DEVNULL, text=True, encoding="utf-8", errors="ignore")
            for line in out.splitlines():
                if not line.strip() or line.strip().startswith("Name"):
                    continue
                parts = line.rsplit(" ", 1)
                if len(parts) == 2:
                    left, pid_str = parts
                    name_cmd = left.strip()
                    name, cmdline = (name_cmd.split(None, 1) + [None])[:2]
                    yield {"pid": pid_str.strip(), "name": name, "exe": None, "cmdline": cmdline, "user": None}
        except Exception:
            try:
                cmd = ["tasklist", "/fo", "CSV"]
                out = subprocess.check_output(cmd, stderr=subprocess.DEVNULL, text=True, encoding="utf-8", errors="ignore")
                reader = csv.reader(out.splitlines())
                next(reader, None)
                for row in reader:
                    name = row[0]
                    pid = row[1]
                    yield {"pid": pid, "name": name, "exe": None, "cmdline": None, "user": None}
            except Exception:
                return iter(())
    else:
        try:
            cmd = ["sh", "-lc", "ps -eo pid,comm,args"]
            out = subprocess.check_output(cmd, stderr=subprocess.DEVNULL, text=True, encoding="utf-8", errors="ignore")
            for line in out.splitlines()[1:]:
                parts = line.strip().split(None, 2)
                if not parts:
                    continue
                pid = parts[0]
                name = parts[1] if len(parts) > 1 else None
                args = parts[2] if len(parts) > 2 else None
                yield {"pid": pid, "name": name, "exe": None, "cmdline": args, "user": None}
        except Exception:
            return iter(())
