#!/usr/bin/env python3
"""Test zkg installation, loading, regression tests, and removal in isolation.

Run after committing package changes: python3 tests/package.py [--cluster] [--version TAG]
Tests the committed checkout; does not modify the user's zkg configuration.
Requires Git, zkg, Zeek, and Python 3. No package-index access is needed.
"""
import argparse
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
NAME = "zeek-mptcp-detect"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cluster", action="store_true")
    parser.add_argument("--version", help="Install this tag, branch, or commit via zkg")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    zkg = shutil.which("zkg")
    zeek = shutil.which(os.environ.get("ZEEK", "zeek"))
    assert zkg and zeek and shutil.which("git"), "Git, zkg, and Zeek must be in PATH"
    out = args.output.resolve() if args.output else Path(tempfile.mkdtemp(prefix="mptcp-zkg-"))
    out.mkdir(parents=True, exist_ok=True)
    print(f"Packaging test artifacts: {out}", flush=True)

    def run(cmd, expected=0):
        result = subprocess.run([str(x) for x in cmd], cwd=out,
                                text=True, capture_output=True, timeout=120)
        if result.returncode != expected:
            raise AssertionError(f"{cmd!r}\n{result.stdout}\n{result.stderr}")
        return result.stdout

    print(run([zkg, "--version"]).strip(), flush=True)
    print(run([zeek, "--version"]).strip(), flush=True)
    # Clone committed files under the canonical repository name. Local Git
    # objects are copied, so tests never modify or share the source's .git.
    source = out / "source" / NAME
    run(["git", "clone", "--no-hardlinks", ROOT, source])
    config = out / "zkg.ini"
    config.write_text(f"""[sources]
[paths]
state_dir = {out / 'state'}
script_dir = {out / 'scripts'}
plugin_dir = {out / 'plugins'}
bin_dir = {out / 'bin'}
""")
    zkg_cmd = [zkg, "--configfile", config]

    def installed(cmd, expected=0):
        # Use zkg's real environment. All variable arguments are positional
        # shell parameters, rather than interpolated into shell source.
        return run(["/bin/sh", "-c",
                    'eval "$("$1" --configfile "$2" env)"; shift 2; exec "$@"',
                    "package-test", zkg, config, *cmd], expected)

    version_args = ["--version", args.version] if args.version else []
    install_output = run([*zkg_cmd, "install", "--force", *version_args, source])
    (out / "install.txt").write_text(install_output)
    print(install_output.strip(), flush=True)
    installed_dir = out / "scripts" / "packages" / NAME
    assert {f.name for f in installed_dir.iterdir()} == {"__load__.zeek", "main.zeek"}
    for name in ("__load__.zeek", "main.zeek"):
        assert (installed_dir / name).read_bytes() == (source / "scripts" / name).read_bytes()

    # Both documented loading methods must resolve the installed package.
    assertion = 'if ( MPTCP::notice_on_attempt ) exit(1); print MPTCP::Established;'
    for load in (NAME, "packages"):
        assert "MPTCP::Established" in installed([zeek, load, "-e", assertion])
    print("PASS zkg install, canonical package load, and @load packages", flush=True)

    # Reuse all packet assertions against the installed package. zkg's own
    # install/test commands separately test its temporary staging installation.
    command = [sys.executable, source / "tests" / "run.py", "--load", NAME,
               "--output", out / "installed-tests"]
    if args.cluster:
        command.append("--cluster")
    print(installed(command).strip(), flush=True)

    run([*zkg_cmd, "unload", "--force", NAME])
    load_check = 'print lookup_ID("MPTCP::Established");'
    assert installed([zeek, "packages", "-e", load_check]).strip() == "<unknown id>"
    # An unloaded package remains explicitly loadable.
    assert "MPTCP::Established" in installed([zeek, NAME, "-e", assertion])
    run([*zkg_cmd, "load", NAME])
    assert "MPTCP::Established" in installed([zeek, "packages", "-e", assertion])
    run([*zkg_cmd, "remove", "--force", NAME])
    assert not installed_dir.exists()
    installed([zeek, NAME, "-e", assertion], expected=1)
    print("PASS zkg unload, reload, and clean removal", flush=True)


if __name__ == "__main__":
    main()
