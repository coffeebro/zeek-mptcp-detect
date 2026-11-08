# zeek-mptcp-detect

Detect attempted and established Multipath TCP on standalone Zeek or a Zeek
cluster. Supports MPTCP v0 (RFC 6824) and v1 (RFC 8684). Requires Zeek 8.0 or
newer. No external Zeek plugins or Python dependencies are needed at runtime.

## Behavior

| Evidence | Detection | Notice |
| --- | --- | --- |
| Initial SYN containing a correctly sized MP_CAPABLE option | `attempted`, `mp_capable_syn` | Optional; off by default |
| Initial SYN containing a correctly sized MP_JOIN option | `attempted`, `mp_join_syn` | Optional; off by default |
| Complete, consistent MP_CAPABLE SYN / SYN-ACK / ACK exchange | `established`, `mp_capable_handshake` | Always requested |
| Structurally valid DSS in both directions of a TCP flow | `established`, `bidirectional_dss` | Always requested |

Attempt logging runs even when attempt notices are disabled. Each TCP flow
generates at most one attempt record and one establishment record, and at most
one notice of each type. Retransmissions do not repeat these detections.
Normal site `Notice::policy` rules can still change actions or suppress notices.

An attempt is an observation, not a verdict that the connection failed. A
successful connection can produce both stages. An attempt with no establishment
record may mean fallback, failure, incomplete capture, or unsupported signaling.

### What "established" means

For `mp_capable_handshake`, the script checks packet direction, SYN/ACK flags,
TCP sequence and acknowledgment numbers, known option lengths, a consistent
version, supported capability flags, checksum negotiation, and the responder
key echoed in the final ACK. For v0 it also checks the repeated initiator key.
It recognizes v1's first-data MP_CAPABLE format. A SYN-ACK by itself does not
establish MPTCP, and an ordinary final ACK does not complete MPTCP negotiation.

`bidirectional_dss` is an independent form of protocol evidence. It allows
detection when the handshake was missed or when an additional subflow appears
on a different worker. DSS lengths and flag combinations are checked. A single
DSS direction, a malformed DSS, or a zero-length infinite mapping is insufficient.
To require a captured MP_CAPABLE handshake instead, disable this path:

```zeek
redef MPTCP::confirm_from_bidirectional_dss = F;
```

These are passive observations at the sensor, not proof of delivery at an
endpoint. The script does not validate DSS data checksums, data acknowledgments
against the MPTCP data sequence space, or MP_JOIN HMACs. It therefore does not
classify a three-packet MP_JOIN exchange alone as successful. MP_JOIN subflows
can be confirmed by the bidirectional DSS path. This conservative choice may
leave an idle, successfully joined backup subflow unconfirmed.

## Installation

### With zkg (recommended)

Requires Zeek 8.0+, zkg 2.12+, Git, and Python 3 for the installation tests.
Configure zkg for your Zeek installation with `zkg autoconfig` if it is not
already configured. Install the tagged release:

```sh
zkg install --version v0.1.0 https://github.com/coffeebro/zeek-mptcp-detect
```

The repository is private, so Git must be authenticated as an account with
access. If you use GitHub SSH authentication, use this URL instead:

```sh
zkg install --version v0.1.0 git@github.com:coffeebro/zeek-mptcp-detect.git
```

zkg runs the regression tests and marks the installed package as loaded. Add
this to `local.zeek` to load packages enabled by zkg:

```zeek
@load packages

# Optional: also issue notices for connection attempts; defaults to F.
redef MPTCP::notice_on_attempt = T;
```

Alternatively, load just this package with `@load zeek-mptcp-detect`. Success
notices are enabled in either case. Keep your `redef` settings in local policy,
so package upgrades do not overwrite them.

For a standalone capture using the installed package:

```sh
zeek -r capture.pcap zeek-mptcp-detect
```

For a user-scoped or custom zkg installation, first run `eval "$(zkg env)"` in
the shell where you will run Zeek. For ZeekControl, configure its `SitePolicyPath`
to include the directory reported by `zkg config script_dir` if it is not
already on the policy search path.

To track future releases rather than explicitly select a version:

```sh
zkg install https://github.com/coffeebro/zeek-mptcp-detect
```

This direct Git URL works without a listing in the public Zeek package index.
The package name for `zkg list`, `zkg load`, `zkg unload`, and `zkg remove` is
`zeek-mptcp-detect`.

### Manual installation

Copy the contents of `scripts/` into an `mptcp/` directory on Zeek's script
search path, for example `<zeek-prefix>/share/zeek/site/mptcp/`:

```text
site/
  local.zeek
  mptcp/
    __load__.zeek
    main.zeek
```

Add to `local.zeek`:

```zeek
@load mptcp

# Optional: also issue notices for connection attempts.
redef MPTCP::notice_on_attempt = T;
```

Omit the `redef` line, or set it to `F`, for notices only on establishment.
Establishment notices are always requested when the package detects success.
The notice types are `MPTCP::Attempted` and `MPTCP::Established`.

With ZeekControl, distribute the same package and configuration to all nodes,
then use the normal `zeekctl check` and `zeekctl deploy` workflow. This applies
to both manual and zkg installations.

For a standalone offline run, no installation is necessary:

```sh
zeek -r capture.pcap /absolute/path/to/zeek-mptcp-detect/scripts
```

To enable attempt notices in that run:

```sh
zeek -r capture.pcap /absolute/path/to/zeek-mptcp-detect/scripts \
    'MPTCP::notice_on_attempt=T'
```

For standalone live monitoring, load it with the rest of your usual policy:

```sh
zeek -i eth0 local /absolute/path/to/zeek-mptcp-detect/scripts
```

## Standalone and cluster operation

The identical scripts support both deployment modes. On standalone Zeek,
detection, notices, and logging run locally. In a cluster:

- Packet analysis runs only on workers. Handshake state belongs to the local
  Zeek `connection` record and is freed with that connection.
- Log stream definitions load on every node. `Log::write()` uses Zeek's normal
  logging configuration, sending records to the logger or manager-as-logger.
- `NOTICE()` uses the built-in Notice framework. In current Zeek, notice policy
  and actions run on the detecting node; the manager distributes suppression
  information. No custom Broker messages or replicated connection tables are used.
- Local connection flags prevent repeat reports over the connection's entire
  lifetime. The notice identifier is its UID; attempt and establishment are
  separate notice types and do not suppress each other.

Use symmetric, flow-affine load balancing: both directions of a given TCP
5-tuple must reach the same worker. Splitting one TCP handshake across workers
prevents this script from validating it. Packet loss, worker restarts, and
asymmetric visibility can also prevent confirmation.

Different subflows of the same MPTCP session may reach different workers. Each
is detected independently. This package does not correlate MP_JOIN tokens with
the initial MP_CAPABLE keys, merge multiple UIDs into one MPTCP session, or
reassemble an MPTCP application stream. One notice is per detected TCP flow,
not per logical MPTCP session across all subflows. Duplicate sensor feeds are
not globally deduplicated; Zeek's suppression synchronization is asynchronous.

## Logs

`mptcp.log` is an event log with:

| Field | Meaning |
| --- | --- |
| `ts` | Time the evidence was detected |
| `uid`, `id` | Zeek TCP connection UID and endpoints |
| `stage` | `attempted` or `established` |
| `evidence` | One of the four evidence strings listed above |
| `version` | Version from MP_CAPABLE, if observed; absent for DSS-only/MP_JOIN-only detection |
| `node` | Worker name or `standalone` |

For an attempt, `version` is the offered version. An unsupported future version
can be logged as an attempt but cannot satisfy the MP_CAPABLE success checks.
For DSS confirmation following an attempt, the recorded version remains the
observed offer; DSS alone does not negotiate or identify a version.

`conn.log` gains four optional fields for detected flows:

- `mptcp_attempted`: whether an initial MP_CAPABLE or MP_JOIN SYN was observed.
- `mptcp_established`: whether the configured success criteria were satisfied.
- `mptcp_version`: version from MP_CAPABLE, if available.
- `mptcp_evidence`: latest reported evidence, with establishment superseding an attempt.

Missing fields mean no reportable detection. `F` means that particular evidence
was not observed, not proof that it never occurred. The MPTCP endpoint keys are
kept only in transient connection state and are not written to these logs.

## Operational limits

- MPTCP may use one subflow. Detection does not prove concurrent use of multiple
  network paths or multiple interfaces.
- A completed handshake remains a historical detection even if MPTCP later
  falls back to ordinary TCP. This is not a continuous connection-mode tracker.
- Unknown versions, unsupported crypto/extension flags, simultaneous open, and
  partial or inconsistently ordered handshake captures are not confirmed by
  the MP_CAPABLE path. Valid bidirectional DSS can independently provide evidence.
- The sensor needs visible TCP headers and options. Application TLS does not
  conceal TCP options, but an encrypted outer tunnel can conceal its inner TCP.
- `tcp_options` is a low-level event raised for all TCP headers with options.
  Even the early return for already detected connections does not eliminate
  Zeek's event-generation and option-parsing cost. Benchmark this package on
  representative traffic before enabling it on a busy sensor.
- Packet context is read synchronously inside the native `tcp_options` handler,
  checked against the connection endpoints, and never read in a scheduled or
  remote event. If the available header cannot be matched to that TCP flow,
  the packet is ignored rather than used to assert success.

## Verification

The test suite builds valid-checksum Ethernet/IPv4/IPv6 PCAPs with Python's
standard library, runs real Zeek, and checks the MPTCP, Notice, and connection
logs. It does not use `-C` or inject synthetic Zeek protocol events.

```sh
python3 tests/run.py
python3 tests/run.py --cluster
```

`zkg test zeek-mptcp-detect` runs these standalone scenarios against the
installed scripts in zkg's isolated test stage. To run the suite against a
package already installed in your environment, including the cluster test:

```sh
python3 tests/run.py --load zeek-mptcp-detect --cluster
```

`--cluster` also starts a manager, logger, and two workers on ephemeral loopback
ports, assigns complete flows to each worker, and verifies the centralized
logs. Temporary test processes are shut down on success or failure. The test
harness selects Broker for reproducible cluster testing; production scripts do
not select a backend. A test-only log batch size of one ensures offline PCAP
records flush even after the packet timestamp clock stops.

Use `ZEEK=/path/to/zeek` for another executable. Test artifacts are kept in a
reported temporary directory; `--output /path/to/new-directory` selects a
destination. See `TESTING.md` for the tested versions and scenario coverage.

## References

- [RFC 8684: MPTCP v1](https://www.rfc-editor.org/rfc/rfc8684.html)
- [RFC 6824: MPTCP v0](https://www.rfc-editor.org/rfc/rfc6824.html)
- [Zeek TCP events](https://docs.zeek.org/en/current/scripts/base/bif/plugins/Zeek_TCP.events.bif.zeek.html)
- [Zeek Notice cluster considerations](https://docs.zeek.org/en/current/frameworks/notice.html#cluster-considerations)
- [Zeek cluster framework](https://docs.zeek.org/en/current/frameworks/cluster.html)
- [Creating zkg packages](https://docs.zeek.org/projects/package-manager/en/stable/package.html)
- [zkg installation and configuration](https://docs.zeek.org/projects/package-manager/en/stable/quickstart.html)
