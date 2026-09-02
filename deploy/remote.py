#!/usr/bin/env python3
"""Run a command on the migration target over SSH.

Credentials come from `.secrets/new_host` (gitignored), never from the command line or
the environment, so they do not end up in shell history, process listings, or a chat
transcript. The file holds one candidate per line; the working line is cached in
`.secrets/.new_host_line` after the first successful authentication.

Usage:
  python3 deploy/remote.py "df -h /"
  python3 deploy/remote.py --put local/path remote/path
  python3 deploy/remote.py --get remote/path local/path
"""

from __future__ import annotations

import argparse
import pathlib
import sys
import warnings

warnings.filterwarnings("ignore")

import paramiko  # noqa: E402

REPO = pathlib.Path(__file__).resolve().parent.parent
SECRET = REPO / ".secrets" / "new_host"
CACHE = REPO / ".secrets" / ".new_host_line"

HOST = "191.215.36.245"
USER = "root"

# Commands run from the project directory by default. `exec_command` starts in the
# login home, which silently made relative paths resolve against /root.
REMOTE_REPO = "/root/Documents/ML-AI-Banking-App"


def connect() -> paramiko.SSHClient:
    candidates = [l.strip() for l in SECRET.read_text().splitlines() if l.strip()]
    order = list(range(len(candidates)))
    if CACHE.exists():
        try:
            cached = int(CACHE.read_text().strip())
            order = [cached] + [i for i in order if i != cached]
        except Exception:
            pass

    last: Exception | None = None
    for index in order:
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
            client.connect(
                HOST, username=USER, password=candidates[index],
                timeout=30, allow_agent=False, look_for_keys=False,
            )
            CACHE.write_text(str(index))
            return client
        except Exception as exc:  # noqa: BLE001
            last = exc
            try:
                client.close()
            except Exception:
                pass
    raise SystemExit(f"could not authenticate to {HOST}: {last}")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("command", nargs="?", help="shell command to run remotely")
    parser.add_argument("--put", nargs=2, metavar=("LOCAL", "REMOTE"))
    parser.add_argument("--get", nargs=2, metavar=("REMOTE", "LOCAL"))
    parser.add_argument("--timeout", type=int, default=1800)
    parser.add_argument("--home", action="store_true", help="run from the login home, not the repo")
    args = parser.parse_args()

    client = connect()
    try:
        if args.put:
            sftp = client.open_sftp()
            sftp.put(args.put[0], args.put[1])
            sftp.close()
            print(f"uploaded {args.put[0]} -> {args.put[1]}")
            return 0
        if args.get:
            sftp = client.open_sftp()
            sftp.get(args.get[0], args.get[1])
            sftp.close()
            print(f"downloaded {args.get[0]} -> {args.get[1]}")
            return 0
        if not args.command:
            parser.error("give a command, --put, or --get")

        command = args.command if args.home else f"cd {REMOTE_REPO} && {args.command}"
        _, stdout, stderr = client.exec_command(command, timeout=args.timeout)
        out = stdout.read().decode("utf-8", "replace")
        err = stderr.read().decode("utf-8", "replace")
        status = stdout.channel.recv_exit_status()
        if out:
            print(out, end="" if out.endswith("\n") else "\n")
        if err:
            print(err, end="" if err.endswith("\n") else "\n", file=sys.stderr)
        return status
    finally:
        client.close()


if __name__ == "__main__":
    raise SystemExit(main())
