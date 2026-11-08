# Validation results

Validated on November 8, 2026, using the official `zeek/zeek:8.0.9` and
`zeek/zeek:9.0.1` container images. Containers had external networking disabled;
cluster processes communicated over the container's loopback interface.

| Test | Zeek 8.0.9 | Zeek 9.0.1 |
| --- | --- | --- |
| Standalone, default configuration | PASS | PASS |
| Standalone, attempt notices enabled | PASS | PASS |
| Standalone, DSS confirmation disabled | PASS | PASS |
| Manager + logger + two workers, attempt notices enabled | PASS | PASS |

Each run exercises 34 generated PCAP scenarios. Assertions check per-flow
attempt/establishment decisions, evidence, version, notice types and counts,
deduplication, and (in standalone runs) the final connection-log fields. Cluster
runs verify that both workers contribute to the centralized logger and that
workers and manager do not write local MPTCP logs. Packet checksums are enabled.

Coverage includes:

- Ordinary TCP, SYN only, SYN/SYN-ACK only, and fallback at either handshake leg.
- Complete v0 and v1 MP_CAPABLE exchanges; v1 final ACK with data, with and
  without the negotiated checksum field.
- Wrong echoed key, incorrect TCP acknowledgment, unsupported crypto flags,
  unsupported extension flags, a reset carrying the final option, and duplicate
  MP_CAPABLE options.
- An unknown protocol version, missing SYN, missing SYN-ACK, and retransmissions.
- IPv6, an 802.1Q VLAN, TCP sequence wraparound, and TCP Fast Open sequence accounting.
- One-direction DSS; bidirectional DSS with 32-bit and 64-bit fields; malformed
  length, illegal flags, infinite fallback mapping, and DSS on a reset.
- Short MP_CAPABLE options and truncated TCP option lengths.
- MP_JOIN exchange without DSS (unconfirmed) and MP_JOIN followed by bilateral
  DSS (confirmed without claiming HMAC validation).

These tests validate passive classification against generated traces, not
interoperability with a running MPTCP endpoint. The first-data checksum fixture
tests option structure; the detector does not validate the checksum value.
Production throughput and alternate cluster backends have not been benchmarked
or integration-tested. The production scripts use only the standard Notice and
Log frameworks and do not select or directly call a cluster backend.

Reproduce from this package's directory with installed Zeek:

```sh
python3 tests/run.py --cluster
```

Or use the official container (Docker must be available):

```sh
docker run --rm --network none \
    --mount "type=bind,src=$PWD,dst=/package,readonly" \
    --workdir /tmp zeek/zeek:9.0.1 \
    python3 /package/tests/run.py --cluster
```

The harness prints its artifact directory. To retain container-generated PCAPs
and logs on the host, mount a separate writable output directory and pass it
with `--output`. Each run expects a fresh output directory.
