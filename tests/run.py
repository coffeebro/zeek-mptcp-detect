#!/usr/bin/env python3
"""Generate checksummed PCAPs and test real Zeek, without Python dependencies.

Run: python3 tests/run.py [--cluster] [--output DIRECTORY]
ZEEK may identify a non-default Zeek executable. Cluster tests use localhost.
"""
import argparse
import collections
import ipaddress
import json
import os
from pathlib import Path
import re
import shutil
import signal
import socket
import struct
import subprocess
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]
ZEEK = os.environ.get("ZEEK", "zeek")
KEY_A = bytes.fromhex("0102030405060708")
KEY_B = bytes.fromhex("1122334455667788")


def checksum(data):
    data += b"\0" * (len(data) % 2)
    total = sum(struct.unpack("!%dH" % (len(data) // 2), data))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def option(data):
    return bytes([30, len(data) + 2]) + data


def capable(version, stage, flags=1, bad_key=False, payload=b""):
    data = bytes([version, flags])
    if stage == 0:
        data += KEY_A if version == 0 else b""
    elif stage == 1:
        data += KEY_B
    else:
        data += KEY_A + (b"X" * 8 if bad_key else KEY_B)
        if version == 1 and payload:
            data += struct.pack("!H", len(payload))
            if flags & 0x80:
                data += b"\0\0"  # Structural test; detector does not check DSS checksums.
    return option(data)


def dss(flags=1, infinite=False):
    data = bytes([0x20, flags])
    if flags & 1:
        data += struct.pack("!Q" if flags & 2 else "!I", 1234)
    if flags & 4:
        data += struct.pack("!Q" if flags & 8 else "!I", 4321)
        data += struct.pack("!IH", 1, 0 if infinite else 3)
    return option(data)


def packet(port, orig=True, flags=0x10, seq=1001, ack=2001,
           opts=b"", payload=b"", ipv6=False, vlan=False):
    src, dst = ("2001:db8::1", "2001:db8::2") if ipv6 else ("192.0.2.1", "198.51.100.2")
    if not orig:
        src, dst = dst, src
    saddr, daddr = ipaddress.ip_address(src).packed, ipaddress.ip_address(dst).packed
    opts += b"\0" * (-len(opts) % 4)
    assert len(opts) <= 40
    sport, dport = (port, 443) if orig else (443, port)
    tcp = struct.pack("!HHIIBBHHH", sport, dport, seq & 0xFFFFFFFF,
                      ack & 0xFFFFFFFF, ((20 + len(opts)) // 4) << 4,
                      flags, 65535, 0, 0) + opts + payload
    pseudo = (saddr + daddr + struct.pack("!I3xB", len(tcp), 6) if ipv6 else
              saddr + daddr + struct.pack("!BBH", 0, 6, len(tcp)))
    tcp = tcp[:16] + struct.pack("!H", checksum(pseudo + tcp)) + tcp[18:]
    if ipv6:
        ip = struct.pack("!IHBB", 6 << 28, len(tcp), 6, 64) + saddr + daddr
    else:
        ip = struct.pack("!BBHHHBBH", 0x45, 0, 20 + len(tcp), 1, 0, 64, 6, 0) + saddr + daddr
        ip = ip[:10] + struct.pack("!H", checksum(ip)) + ip[12:]
    ether_type = 0x86DD if ipv6 else 0x0800
    eth = bytes.fromhex("020000000002020000000001")
    eth += struct.pack("!HHH", 0x8100, 42, ether_type) if vlan else struct.pack("!H", ether_type)
    return eth + ip + tcp


def handshake(port, version=1, offer=True, reply=True, final=True, bad_key=False,
              flags=1, payload=b"", ipv6=False, vlan=False, wrong_ack=False,
              initial_seq=1000, final_flags=0x10, duplicate=False, syn_payload=b""):
    a = capable(version, 0, flags) if offer else b""
    b = capable(version, 1, flags) if reply else b""
    c = capable(version, 2, flags, bad_key, payload) if final else b""
    if duplicate:
        c += c
    after_syn = (initial_seq + 1 + len(syn_payload)) & 0xFFFFFFFF
    kw = dict(ipv6=ipv6, vlan=vlan)
    return [packet(port, flags=2, seq=initial_seq, ack=0, opts=a, payload=syn_payload, **kw),
            packet(port, False, flags=0x12, seq=2000, ack=after_syn, opts=b, **kw),
            packet(port, flags=final_flags, seq=after_syn,
                   ack=2002 if wrong_ack else 2001, opts=c, payload=payload, **kw)]


def fixtures():
    cases = []

    def add(name, build, attempt=True, success=False, evidence=None, version=1):
        port = 40000 + len(cases)
        cases.append(dict(name=name, port=port, packets=build(port), attempt=attempt,
                          success=success, evidence=evidence, version=version))

    add("plain_tcp", lambda p: handshake(p, offer=False, reply=False, final=False), False, version=None)
    add("syn_only", lambda p: handshake(p)[:1])
    add("fallback_synack", lambda p: handshake(p, reply=False, final=False))
    add("fallback_final_ack", lambda p: handshake(p, final=False))
    add("synack_only_no_completion", lambda p: handshake(p)[:2])
    add("v1_success", lambda p: handshake(p), success=True, evidence="mp_capable_handshake")
    add("v0_success", lambda p: handshake(p, version=0), success=True,
        evidence="mp_capable_handshake", version=0)
    add("v1_data_final", lambda p: handshake(p, payload=b"abc"), success=True,
        evidence="mp_capable_handshake")
    add("v1_checksum_data_final", lambda p: handshake(p, flags=0x81, payload=b"abc"),
        success=True, evidence="mp_capable_handshake")
    add("wrong_key", lambda p: handshake(p, bad_key=True))
    add("wrong_tcp_ack", lambda p: handshake(p, wrong_ack=True))
    add("unsupported_crypto", lambda p: handshake(p, flags=0))
    add("unsupported_extension", lambda p: handshake(p, flags=0x41))
    add("rst_final", lambda p: handshake(p, final_flags=0x14))
    add("duplicate_capable", lambda p: handshake(p, duplicate=True))
    add("unknown_version", lambda p: handshake(p, version=2), version=2)
    add("missing_syn", lambda p: handshake(p)[1:], False, version=None)
    add("missing_synack", lambda p: handshake(p)[::2])
    add("retransmissions", lambda p: [x for x in handshake(p) for _ in range(4)],
        success=True, evidence="mp_capable_handshake")
    add("ipv6", lambda p: handshake(p, ipv6=True), success=True, evidence="mp_capable_handshake")
    add("vlan", lambda p: handshake(p, vlan=True), success=True, evidence="mp_capable_handshake")
    add("sequence_wrap", lambda p: handshake(p, initial_seq=0xFFFFFFFF),
        success=True, evidence="mp_capable_handshake")
    add("tcp_fast_open", lambda p: handshake(p, syn_payload=b"abc"),
        success=True, evidence="mp_capable_handshake")
    add("single_direction_dss", lambda p: [packet(p, opts=dss())], False, version=None)
    add("midstream_dss", lambda p: [packet(p, opts=dss(4), payload=b"abc"),
        packet(p, False, seq=2001, ack=1004, opts=dss())], False, True,
        "bidirectional_dss", None)
    add("midstream_dss_64", lambda p: [packet(p, opts=dss(15)),
        packet(p, False, seq=2001, ack=1001, opts=dss(3))], False, True,
        "bidirectional_dss", None)
    add("malformed_dss", lambda p: [packet(p, opts=option(b"\x20\x03\x01")),
        packet(p, False, seq=2001, ack=1001, opts=dss())], False, version=None)
    add("illegal_dss_flags", lambda p: [packet(p, opts=option(b"\x20\x02")),
        packet(p, False, seq=2001, ack=1001, opts=dss())], False, version=None)
    add("infinite_mapping", lambda p: [packet(p, opts=dss(4, infinite=True)),
        packet(p, False, seq=2001, ack=1001, opts=dss())], False, version=None)
    add("dss_on_rst", lambda p: [packet(p, opts=dss()),
        packet(p, False, flags=0x14, seq=2001, ack=1001, opts=dss())], False, version=None)
    add("short_capable", lambda p: [packet(p, flags=2, seq=1000, ack=0,
        opts=option(b"\x00\x01"))], False, version=None)
    add("truncated_option", lambda p: [packet(p, flags=2, seq=1000, ack=0,
        opts=b"\x1e\x0c\x00\x01")], False, version=None)

    def join(p, active=False):
        pkts = [packet(p, flags=2, seq=1000, ack=0, opts=option(b"\x10\x00" + b"T"*4 + b"N"*4)),
                packet(p, False, flags=0x12, seq=2000, ack=1001,
                       opts=option(b"\x10\x00" + b"H"*8 + b"R"*4)),
                packet(p, opts=option(b"\x10\x00" + b"H"*20)),
                packet(p, False, seq=2001, ack=1001)]
        if active:
            pkts += [packet(p, opts=dss()), packet(p, False, seq=2001, ack=1001, opts=dss())]
        return pkts

    add("join_unverified_handshake", join, version=None)
    add("join_dss_confirmation", lambda p: join(p, True), success=True,
        evidence="bidirectional_dss", version=None)
    return cases


def write_pcap(path, packets):
    with path.open("wb") as out:
        out.write(struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
        start = int(time.time())
        for i, frame in enumerate(packets):
            out.write(struct.pack("<IIII", start + i // 1000, (i % 1000) * 1000,
                                  len(frame), len(frame)))
            out.write(frame)


def rows(path):
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


def check(logdir, cases, attempts, dss_enabled=True, cluster=False):
    observed = collections.defaultdict(list)
    notices = collections.defaultdict(list)
    for rec in rows(logdir / "mptcp.log"):
        observed[rec["id.orig_p"]].append(rec)
        assert rec["node"].startswith("worker-") if cluster else rec["node"] == "standalone"
    for rec in rows(logdir / "notice.log"):
        if rec["note"].startswith("MPTCP::"):
            notices[rec["id.orig_p"]].append(rec["note"])
    for case in cases:
        success = case["success"] and (dss_enabled or case["evidence"] != "bidirectional_dss")
        expected_stages = (["attempted"] if case["attempt"] else []) + (["established"] if success else [])
        got = observed.pop(case["port"], [])
        assert [r["stage"] for r in got] == expected_stages, (case["name"], got, expected_stages)
        for rec in got:
            assert rec.get("version") == case["version"], (case["name"], rec)
            if rec["stage"] == "established":
                assert rec["evidence"] == case["evidence"], (case["name"], rec)
        expected_notes = (["MPTCP::Attempted"] if case["attempt"] and attempts else [])
        expected_notes += ["MPTCP::Established"] if success else []
        assert sorted(notices.pop(case["port"], [])) == sorted(expected_notes), case["name"]
    assert not observed and not notices, (observed, notices)


def run_standalone(out, cases):
    pcap = out / "traffic.pcap"
    write_pcap(pcap, [p for case in cases for p in case["packets"]])
    for mode, attempts, dss_enabled in [("default", False, True), ("attempt_notices", True, True),
                                        ("handshake_only", False, False)]:
        dest = out / mode
        dest.mkdir()
        config = dest / "config.zeek"
        config.write_text("redef LogAscii::use_json = T;\n" +
                          f"redef MPTCP::notice_on_attempt = {'T' if attempts else 'F'};\n" +
                          f"redef MPTCP::confirm_from_bidirectional_dss = {'T' if dss_enabled else 'F'};\n")
        # Intentionally no -C: fixtures carry valid IP and TCP checksums.
        result = subprocess.run([ZEEK, "-r", str(pcap), str(ROOT / "scripts"), str(config)],
                                cwd=dest, text=True, capture_output=True, timeout=30)
        (dest / "stderr").write_text(result.stderr)
        assert result.returncode == 0 and not result.stderr, result.stderr
        check(dest, cases, attempts, dss_enabled)
        conn = {r["id.orig_p"]: r for r in rows(dest / "conn.log")}
        for case in cases:
            success = case["success"] and (dss_enabled or case["evidence"] != "bidirectional_dss")
            if case["attempt"] or success:
                assert conn[case["port"]]["mptcp_attempted"] == case["attempt"], case["name"]
                assert conn[case["port"]]["mptcp_established"] == success, case["name"]
            else:
                assert "mptcp_established" not in conn[case["port"]], case["name"]
        print(f"PASS standalone {mode}: {len(cases)} PCAP scenarios", flush=True)


def free_ports(count):
    sockets = [socket.socket() for _ in range(count)]
    try:
        for s in sockets:
            s.bind(("127.0.0.1", 0))
        return [s.getsockname()[1] for s in sockets]
    finally:
        for s in sockets:
            s.close()


def run_cluster(out, cases):
    dest = out / "cluster"
    dest.mkdir()
    names = ["logger", "manager", "worker-1", "worker-2"]
    ports = free_ports(len(names))
    layout = "redef Cluster::nodes = {\n"
    for name, port in zip(names, ports):
        role = "WORKER" if name.startswith("worker") else name.upper()
        manager = ', $manager="manager"' if name != "manager" else ""
        layout += f' ["{name}"] = [$node_type=Cluster::{role}, $ip=127.0.0.1, $p={port}/tcp{manager}],\n'
    (dest / "cluster-layout.zeek").write_text(layout + "};\n")
    driver = dest / "driver.zeek"
    version = subprocess.check_output([ZEEK, "--version"], text=True)
    major = int(re.search(r"\d+", version).group())
    # Broker is the default in Zeek 8; explicit backend selection was added in 9.
    backend_load = "@load frameworks/cluster/backend/broker\n" if major >= 9 else ""
    driver.write_text(f'''{backend_load}\
@load {ROOT / 'scripts'}
@load frameworks/cluster/experimental
redef Cluster::manager_is_logger = F;
redef LogAscii::use_json = T;
redef Log::default_rotation_interval = 0sec;
redef Log::flush_interval = 0.05sec;
redef Broker::log_batch_size = 1;
redef MPTCP::notice_on_attempt = T;
redef exit_only_after_terminate = T;
event zeek_init() {{
    if ( Cluster::local_node_type() == Cluster::WORKER )
        suspend_processing();
}}
event Cluster::Experimental::cluster_started() {{
    if ( Cluster::local_node_type() == Cluster::WORKER )
        continue_processing();
}}
''')
    # Real separate worker processes each receive complete, distinct TCP flows.
    for i in range(2):
        write_pcap(dest / f"worker-{i+1}.pcap", [p for c in cases[i::2] for p in c["packets"]])
    zeek_config = str(Path(shutil.which(ZEEK)).with_name("zeek-config"))
    default_path = subprocess.check_output([zeek_config, "--zeekpath"], text=True).strip()
    env = dict(os.environ, ZEEKPATH=str(dest) + ":" + default_path)
    procs = []
    handles = []
    try:
        for name in names:
            cwd = dest / name
            cwd.mkdir()
            stdout, stderr = (cwd / "stdout").open("w"), (cwd / "stderr").open("w")
            handles.extend([stdout, stderr])
            cmd = [ZEEK]
            if name.startswith("worker"):
                cmd += ["-r", str(dest / f"{name}.pcap")]
            cmd.append(str(driver))
            procs.append(subprocess.Popen(cmd, cwd=cwd, env=dict(env, CLUSTER_NODE=name),
                                          stdout=stdout, stderr=stderr))
            if name in ("logger", "manager"):
                ready_deadline = time.monotonic() + 10
                while time.monotonic() < ready_deadline:
                    assert procs[-1].poll() is None, (name, "exited before listening")
                    if any("listening on" in r.get("message", "") for r in rows(cwd / "cluster.log")):
                        break
                    time.sleep(0.05)
                else:
                    raise AssertionError((name, "did not start listening"))
        expected = sum(c["attempt"] + c["success"] for c in cases)
        deadline = time.monotonic() + 25
        while time.monotonic() < deadline:
            assert all(p.poll() is None for p in procs), "Cluster process exited; inspect stderr"
            try:
                if len(rows(dest / "logger" / "mptcp.log")) >= expected and len(rows(dest / "logger" / "notice.log")) >= expected:
                    break
            except json.JSONDecodeError:
                pass  # A logger may be in the middle of flushing a line.
            time.sleep(0.1)
        else:
            raise AssertionError("Cluster logs timed out; inspect cluster/*/stderr and cluster.log")
        check(dest / "logger", cases, True, cluster=True)
        for name in names:
            unexpected = [line for line in (dest / name / "stderr").read_text().splitlines()
                          if line not in ("processing suspended", "processing continued")]
            assert not unexpected, (name, unexpected)
        for name in ("manager", "worker-1", "worker-2"):
            assert not rows(dest / name / "mptcp.log"), name
        assert {r["node"] for r in rows(dest / "logger" / "mptcp.log")} == {"worker-1", "worker-2"}
        print(f"PASS cluster: manager, logger, two workers; {len(cases)} PCAP scenarios", flush=True)
    finally:
        for p in procs:
            if p.poll() is None:
                p.send_signal(signal.SIGTERM)
        for p in procs:
            try:
                p.wait(timeout=5)
            except subprocess.TimeoutExpired:
                p.kill()
                p.wait()
        for h in handles:
            h.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cluster", action="store_true")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    assert shutil.which(ZEEK), f"Zeek not found: {ZEEK}"
    out = args.output.resolve() if args.output else Path(tempfile.mkdtemp(prefix="zeek-mptcp-tests-"))
    out.mkdir(parents=True, exist_ok=True)
    print(subprocess.check_output([ZEEK, "--version"], text=True).strip(), flush=True)
    print(f"Test artifacts: {out}", flush=True)
    cases = fixtures()
    run_standalone(out, cases)
    if args.cluster:
        run_cluster(out, cases)


if __name__ == "__main__":
    main()
