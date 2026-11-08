##! Passive MPTCP detection for standalone Zeek and flow-affine clusters.
##! See README.md for the meaning and limits of each evidence category.

@load base/frameworks/notice
@load base/protocols/conn

module MPTCP;

export {
    redef enum Notice::Type += {
        ## An MP_CAPABLE or MP_JOIN initial SYN was observed.
        Attempted,
        ## A validated MP_CAPABLE exchange or bidirectional DSS was observed.
        Established
    };

    redef enum Log::ID += { LOG };

    ## Attempt detection and logging always run; this controls only notices.
    option notice_on_attempt = F;

    ## Accept structurally valid DSS in both directions as evidence when the
    ## original handshake is missing (including additional MP_JOIN subflows).
    option confirm_from_bidirectional_dss = T;

    type Info: record {
        ts: time &log;
        uid: string &log;
        id: conn_id &log;
        stage: string &log;
        evidence: string &log;
        version: count &log &optional;
        node: string &log;
    };

    global log_mptcp: event(rec: Info);
    global log_policy: Log::PolicyHook;

    # State is attached to the owning TCP connection, never a global UID table.
    # Zeek frees it with the connection; it is not sent to other workers.
    type State: record {
        attempted: bool &default=F;
        established: bool &default=F;
        version: count &optional;
        syn: string &optional;
        syn_next: count &optional;
        synack: string &optional;
        synack_next: count &optional;
        dss_orig: bool &default=F;
        dss_resp: bool &default=F;
    };
}

redef record connection += { mptcp: State &optional; };
redef record Conn::Info += {
    mptcp_attempted: bool &log &optional;
    mptcp_established: bool &log &optional;
    mptcp_version: count &log &optional;
    mptcp_evidence: string &log &optional;
};

event zeek_init() &priority=5
    {
    # Register on every node so the normal remote logging framework works.
    Log::create_stream(LOG, [$columns=Info, $ev=log_mptcp,
                            $path="mptcp", $policy=log_policy]);
    }

@if ( ! Cluster::is_enabled() || Cluster::local_node_type() == Cluster::WORKER )
function octet(data: string, offset: count): count
    {
    return bytestring_to_count(data[offset:offset+1]);
    }

function ensure_state(c: connection)
    {
    if ( ! c?$mptcp )
        c$mptcp = State();
    }

function report(c: connection, stage: string, evidence: string)
    {
    local s = c$mptcp;
    if ( stage == "attempted" )
        {
        if ( s$attempted )
            return;
        s$attempted = T;
        }
    else
        {
        if ( s$established )
            return;
        s$established = T;
        }

    local rec: Info = [$ts=network_time(), $uid=c$uid, $id=c$id,
                      $stage=stage, $evidence=evidence,
                      $node=Cluster::is_enabled() ? Cluster::node : "standalone"];
    if ( s?$version )
        rec$version = s$version;
    Log::write(LOG, rec);

    if ( c?$conn )
        {
        c$conn$mptcp_attempted = s$attempted;
        c$conn$mptcp_established = s$established;
        c$conn$mptcp_evidence = evidence;
        if ( s?$version )
            c$conn$mptcp_version = s$version;
        }

    if ( stage == "established" || notice_on_attempt )
        NOTICE([$note=stage == "established" ? Established : Attempted,
                $conn=c,
                $msg=fmt("MPTCP %s: %s", stage, evidence),
                $sub=fmt("Evidence applies to TCP flow %s; version=%s", c$uid,
                         s?$version ? cat(s$version) : "unknown"),
                $identifier=c$uid]);
    }

function supported_flags(data: string, version: count): bool
    {
    local flags = octet(data, 1);
    # B changes the option format. Only the specified HMAC algorithm is
    # understood. In v1 C is a separate flag, not a crypto algorithm.
    return (flags & 0x40) == 0 &&
           (flags & (version == 0 ? 0x3f : 0x1f)) == 1;
    }

function capable(c: connection, orig: bool, h: tcp_hdr, data: string)
    {
    if ( |data| < 2 )
        return;

    local v = octet(data, 0) & 0x0f;
    local syn = (h$flags & TH_SYN) != 0;
    local ack = (h$flags & TH_ACK) != 0;
    local s: State;

    if ( orig && syn && ! ack )
        {
        # Unknown versions are still attempts, but never handshake success.
        if ( (v == 0 && |data| != 10) || (v == 1 && |data| != 2) )
            return;
        ensure_state(c);
        s = c$mptcp;
        s$version = v;
        report(c, "attempted", "mp_capable_syn");

        # A changed retransmitted proposal invalidates the old response.
        if ( s?$syn && (s$syn != data ||
                        s$syn_next != (h$seq + 1 + h$dl) % 4294967296) )
            {
            delete s$synack;
            delete s$synack_next;
            }
        delete s$syn;
        delete s$syn_next;
        if ( v > 1 || ! supported_flags(data, v) )
            return;
        s$syn = data;
        s$syn_next = (h$seq + 1 + h$dl) % 4294967296;
        return;
        }

    if ( ! c?$mptcp || ! c$mptcp?$syn ||
         v > 1 || ! supported_flags(data, v) )
        return;

    s = c$mptcp;
    # Only same-version handshakes are validated. A new v0 retry has its own
    # SYN. Unknown future versions are not inferred from their wire length.
    if ( v != (octet(s$syn, 0) & 0x0f) )
        return;

    if ( ! orig && syn && ack && |data| == 10 && h$ack == s$syn_next )
        {
        s$synack = data;
        s$synack_next = (h$seq + 1 + h$dl) % 4294967296;
        return;
        }

    if ( ! orig || syn || ! ack || ! s?$synack ||
         h$seq != s$syn_next || h$ack != s$synack_next )
        return;

    local checksum_required = ((octet(s$syn, 1) | octet(s$synack, 1)) & 0x80) != 0;
    if ( ((octet(data, 1) & 0x80) != 0) != checksum_required )
        return;

    if ( v == 0 || h$dl == 0 )
        {
        if ( |data| != 18 || (v == 0 && h$dl != 0) )
            return;
        }
    else
        {
        # v1's first-data MP_CAPABLE replaces DSS and includes data length.
        if ( |data| != (checksum_required ? 22 : 20) )
            return;
        if ( bytestring_to_count(data[18:20]) == 0 ||
             bytestring_to_count(data[18:20]) < h$dl )
            return;
        }

    # The last ACK must echo the responder key; v0 also repeats the SYN key.
    if ( data[10:18] != s$synack[2:10] ||
         (v == 0 && data[2:10] != s$syn[2:10]) )
        return;

    report(c, "established", "mp_capable_handshake");
    }

function valid_dss(data: string): bool
    {
    if ( |data| < 2 )
        return F;
    local f = octet(data, 1);
    local a = (f & 1) != 0;
    local a64 = (f & 2) != 0;
    local m = (f & 4) != 0;
    local m64 = (f & 8) != 0;
    local fin = (f & 16) != 0;
    if ( (! a && ! m) || (a64 && ! a) || (m64 && ! m) || (fin && ! m) )
        return F;

    local size: count = 2 + (a ? (a64 ? 8 : 4) : 0);
    if ( m )
        {
        size += (m64 ? 8 : 4) + 4 + 2;
        if ( |data| != size && |data| != size + 2 )
            return F;
        # A zero-length (infinite) mapping signals fallback to ordinary TCP.
        if ( bytestring_to_count(data[size-2:size]) == 0 )
            return F;
        }
    else if ( |data| != size )
        return F;
    return T;
    }

event tcp_options(c: connection, is_orig: bool, options: TCP::OptionList)
    {
    if ( c?$mptcp && c$mptcp$established )
        return;

    local relevant = F;
    local subtypes: set[count] = {};
    local st: count;
    for ( _, o in options )
        {
        if ( o$kind != 30 || ! o?$data || |o$data| < 1 ||
             o$length != |o$data| + 2 )
            next;
        st = octet(o$data, 0) / 16;
        if ( st > 2 )
            next;
        # Ambiguous duplicate signaling must not combine into a handshake.
        if ( st in subtypes )
            return;
        add subtypes[st];
        relevant = T;
        }
    if ( ! relevant || (0 in subtypes && 1 in subtypes) )
        return;

    # Read packet context synchronously in this native packet-level event.
    # Never defer this call via schedule/event or perform it on a remote node.
    local p = get_current_packet_header();
    if ( ! p?$tcp || (! p?$ip && ! p?$ip6) )
        return;
    local h = p$tcp;
    local src = p?$ip ? p$ip$src : p$ip6$src;
    local dst = p?$ip ? p$ip$dst : p$ip6$dst;
    if ( src != (is_orig ? c$id$orig_h : c$id$resp_h) ||
         dst != (is_orig ? c$id$resp_h : c$id$orig_h) ||
         h$sport != (is_orig ? c$id$orig_p : c$id$resp_p) ||
         h$dport != (is_orig ? c$id$resp_p : c$id$orig_p) ||
         (h$flags & TH_RST) != 0 ||
         ((h$flags & TH_SYN) != 0 && (h$flags & TH_FIN) != 0) )
        return;

    for ( _, o in options )
        {
        if ( o$kind != 30 || ! o?$data || |o$data| < 2 ||
             o$length != |o$data| + 2 )
            next;
        st = octet(o$data, 0) / 16;
        if ( st == 0 )
            capable(c, is_orig, h, o$data);
        else if ( st == 1 && is_orig && (h$flags & TH_SYN) != 0 &&
                  (h$flags & TH_ACK) == 0 && |o$data| == 10 )
            {
            ensure_state(c);
            report(c, "attempted", "mp_join_syn");
            }
        else if ( st == 2 && confirm_from_bidirectional_dss &&
                  (h$flags & TH_SYN) == 0 && (h$flags & TH_ACK) != 0 &&
                  valid_dss(o$data) )
            {
            ensure_state(c);
            if ( is_orig )
                c$mptcp$dss_orig = T;
            else
                c$mptcp$dss_resp = T;
            if ( c$mptcp$dss_orig && c$mptcp$dss_resp )
                report(c, "established", "bidirectional_dss");
            }
        }
    }
@endif
