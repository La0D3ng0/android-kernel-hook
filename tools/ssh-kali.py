#!/usr/bin/env python3
"""Run a command on the Kali build VM over SSH (paramiko).

Usage:
    python tools/ssh-kali.py "<command>"
    python tools/ssh-kali.py --file <local-script>   # uploads and runs via bash
    python tools/ssh-kali.py --upload <local> <remote>
    python tools/ssh-kali.py --download <remote> <local>

Environment defaults: host 192.168.50.128, user laodeng, password 0.
"""
import os
import sys

import paramiko

HOST = os.environ.get("KALI_HOST", "192.168.50.128")
USER = os.environ.get("KALI_USER", "laodeng")
PASSWORD = os.environ.get("KALI_PASSWORD", "0")


def connect():
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(
        HOST,
        username=USER,
        password=PASSWORD,
        timeout=20,
        look_for_keys=False,
        allow_agent=False,
        banner_timeout=20,
        auth_timeout=20,
    )
    return client


def run(client, command, use_sudo=False, timeout=1800):
    if use_sudo:
        command = "sudo -S -p '' sh -c " + shlex_quote(command)
        stdin, stdout, stderr = client.exec_command(command, timeout=timeout)
        stdin.write(PASSWORD + "\n")
        stdin.flush()
    else:
        stdin, stdout, stderr = client.exec_command(command, timeout=timeout)
    out = stdout.read().decode(errors="replace")
    err = stderr.read().decode(errors="replace")
    code = stdout.channel.recv_exit_status()
    sys.stdout.write(out)
    if err:
        sys.stderr.write(err)
    return code


def shlex_quote(value):
    return "'" + value.replace("'", "'\\''") + "'"


def main():
    argv = sys.argv[1:]
    if not argv:
        print(__doc__)
        return 2
    client = connect()
    try:
        if argv[0] == "--file":
            path = argv[1]
            script = os.path.basename(path)
            sftp = client.open_sftp()
            sftp.put(path, "/tmp/" + script)
            sftp.close()
            return run(client, "bash /tmp/" + script, use_sudo=False)
        if argv[0] == "--upload":
            sftp = client.open_sftp()
            sftp.put(argv[1], argv[2])
            sftp.close()
            print("uploaded", argv[1], "->", argv[2])
            return 0
        if argv[0] == "--download":
            sftp = client.open_sftp()
            sftp.get(argv[1], argv[2])
            sftp.close()
            print("downloaded", argv[1], "->", argv[2])
            return 0
        return run(client, " ".join(argv), use_sudo=False)
    finally:
        client.close()


if __name__ == "__main__":
    sys.exit(main())
