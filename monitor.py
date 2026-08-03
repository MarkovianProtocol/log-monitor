#!/usr/bin/env python3
"""markovian log monitor — standing watcher + independent audit.

Runs hourly from cron. Each run:
  1. fetches the public witnessed checkpoint, verifies the log's Ed25519
     signature over the signed note, and cryptographically verifies each
     witness cosignature (C2SP cosignature/v1) against the witness keys
     pinned in config.json ("witness_vkeys")
  2. verifies an RFC 6962 consistency proof from the last seen tree head
     to the new one (append-only check — a failure here means fork/rewrite)
  3. fetches leaves added since the last run and matches them against
     watches.json (exact issuer match or substring over raw leaf bytes)
  4. RECOMPUTES the tree root from the leaf bytes the log served (RFC 6962,
     via an incremental Merkle fringe kept in state) and requires it to equal
     the signed checkpoint root — the log's /leaves output is otherwise
     unauthenticated (v3, Cert Spotter model)
  5. emails alerts via Resend. The trusted head advances only past a
     checkpoint that is authenticated (valid log signature AND verified
     witness quorum), consistent with the previous head, AND whose leaves
     reproduce the committed root; any failure leaves the head unchanged.

v3 also: freshness alarm (stale/frozen checkpoint), daily heartbeat so
silence is a signal, atomic state writes with a .bak, hard-stop (not silent
re-baseline) on a missing/corrupt state file, and canonicalized watch
matching (raw substring is evadable by JSON-escaping — a CT concealment
attack). Auth/consistency alerts are sent BEFORE /leaves is touched so a
hostile /leaves cannot mute a fork alarm.

What this verifies: the log signature; each pinned witness cosignature
(correct 4-byte keyhash and a valid Ed25519 signature over the
"cosignature/v1\ntime <t>\n" + note-body message) — quorum counts only
VERIFIED cosignatures; and append-only consistency. A pinned witness whose
cosignature FAILS verification raises its own alert (forgery signal).
Cosigner names with no pinned key are counted and logged, never trusted.
Post-quantum (non-Ed25519) cosignature blobs are skipped, not verified.
It watches the PUBLIC endpoint, so it sees what external clients see.

Flags: --dry-run (no email, print instead), --init (baseline at current
size, no leaf alerts), --once-test-email (send one test alert and exit).
Env: MONITOR_CONFIG=/path/to/config.json overrides the default config
(for testing only; the cron run uses config.json next to this script).
"""
import base64
import hashlib
import json
import os
import ssl
import sys
import time
import urllib.request

BASE = os.path.dirname(os.path.abspath(__file__))
CONFIG_PATH = os.environ.get("MONITOR_CONFIG", os.path.join(BASE, "config.json"))
CONFIG = json.load(open(CONFIG_PATH))
STATE_PATH = os.path.join(BASE, "state.json")
WATCHES_PATH = os.path.join(BASE, "watches.json")

LOG_URL = CONFIG["log_url"].rstrip("/")
VKEY = CONFIG["log_vkey"]  # name+hash8+base64(algbyte+key)
WITNESS_VKEYS = CONFIG.get("witness_vkeys", [])  # name+hash8+base64(0x04+key)
QUORUM_MIN = int(CONFIG.get("quorum_min", 4))
FROM_EMAIL = CONFIG["from_email"]
ALERT_EMAIL = CONFIG["alert_email"]
RESEND_ENV = CONFIG.get("resend_env", "resend.env")


def http_get(path):
    req = urllib.request.Request(LOG_URL + path, headers={"User-Agent": "markovian-monitor/1"})
    with urllib.request.urlopen(req, timeout=30) as r:
        return r.read()


# ── C2SP signed note ──────────────────────────────────────────────────
def parse_vkey(vkey):
    name, _hash, b64 = vkey.split("+", 2)
    raw = base64.b64decode(b64 + "=" * (-len(b64) % 4))
    if raw[0] != 0x01:
        raise ValueError("not an ed25519 note vkey")
    return name, raw[1:33]


def parse_checkpoint(note_bytes):
    text = note_bytes.decode()
    if "\n\n" not in text:
        raise ValueError("no signature section")
    body, sigblock = text.split("\n\n", 1)
    body += "\n"
    lines = body.splitlines()
    origin, size, root_b64 = lines[0], int(lines[1]), lines[2]
    sigs = []  # (name, raw)
    for ln in sigblock.splitlines():
        if ln.startswith("— "):
            _, name, s64 = ln.split(" ", 2)
            sigs.append((name, base64.b64decode(s64 + "=" * (-len(s64) % 4))))
    return body, origin, size, base64.b64decode(root_b64), sigs


def verify_log_sig(body, sigs):
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    name, pub = parse_vkey(VKEY)
    keyhash = hashlib.sha256(name.encode() + b"\n" + b"\x01" + pub).digest()[:4]
    for signame, raw in sigs:
        if signame == name and raw[:4] == keyhash and len(raw) == 68:
            Ed25519PublicKey.from_public_bytes(pub).verify(raw[4:], body.encode())
            return True
    return False


# ── C2SP tlog-cosignature (cosignature/v1) ────────────────────────────
def parse_witness_vkey(vkey):
    """name+hash8+base64(0x04||ed25519_pub) -> (name, keyid4, pub32).

    Keyid is recomputed from name+pubkey per spec (SHA-256(name || 0x0A ||
    0x04 || pub)[:4]); the hex field in the vkey string is informational.
    """
    name, _keyid_hex, b64 = vkey.split("+", 2)
    blob = base64.b64decode(b64 + "=" * (-len(b64) % 4))
    if blob[0] != 0x04:
        raise ValueError(f"{name}: not a cosignature/v1 (0x04) vkey")
    pub = blob[1:33]
    kid = hashlib.sha256(name.encode() + b"\n\x04" + pub).digest()[:4]
    return name, kid, pub


def verify_cosignatures(body, sigs):
    """Verify every cosignature line against the pinned witness keys.

    Returns (verified, invalid, unknown, skipped, newest_ts):
      verified — set of pinned witness names with a valid cosignature
      invalid  — set of (name, reason) for pinned witnesses whose
                 cosignature FAILS verification (forgery signal)
      unknown  — set of cosigner names with no pinned key (not trusted)
      skipped  — count of non-Ed25519-cosignature blobs from pinned names
                 (e.g. post-quantum schemes; wrong length for cosig/v1)
      newest_ts — max cosignature unix timestamp among VERIFIED witnesses,
                 or 0 if none (used for the freshness/withholding check)
    """
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    from cryptography.exceptions import InvalidSignature
    log_name = parse_vkey(VKEY)[0]
    pinned = {}
    for vkey in WITNESS_VKEYS:
        name, kid, pub = parse_witness_vkey(vkey)
        pinned[name] = (kid, pub)
    verified, invalid, unknown = set(), set(), set()
    skipped = 0
    newest_ts = 0
    for name, raw in sigs:
        if name == log_name:
            continue
        if name not in pinned:
            unknown.add(name)
            continue
        if len(raw) != 76:  # keyid(4) + be64 timestamp(8) + ed25519 sig(64)
            skipped += 1
            continue
        kid, pub = pinned[name]
        if raw[:4] != kid:
            invalid.add((name, "keyhash mismatch"))
            continue
        ts = int.from_bytes(raw[4:12], "big")
        msg = b"cosignature/v1\ntime " + str(ts).encode() + b"\n" + body.encode()
        try:
            Ed25519PublicKey.from_public_bytes(pub).verify(raw[12:], msg)
            verified.add(name)
            newest_ts = max(newest_ts, ts)
        except InvalidSignature:
            invalid.add((name, "signature did not verify"))
    return verified, invalid, unknown, skipped, newest_ts


# ── RFC 6962 consistency ──────────────────────────────────────────────
def node_hash(a, b):
    return hashlib.sha256(b"\x01" + a + b).digest()


def verify_consistency(size1, size2, root1, root2, proof):
    if size1 == 0 or size1 == size2:
        return size1 == size2 and root1 == root2 if size1 else True
    node, last = size1 - 1, size2 - 1
    while node & 1:
        node >>= 1
        last >>= 1
    p = iter(proof)
    try:
        fr = sr = next(p) if node else root1
        while node:
            if node & 1:
                c = next(p)
                fr, sr = node_hash(c, fr), node_hash(c, sr)
            elif node < last:
                sr = node_hash(sr, next(p))
            node >>= 1
            last >>= 1
        while last:
            sr = node_hash(sr, next(p))
            last >>= 1
    except StopIteration:
        return False
    return fr == root1 and sr == root2 and sum(1 for _ in p) == 0


# ── RFC 6962 leaf hashing + incremental Merkle fringe (Cert Spotter model) ──
# We recompute the tree root from the leaf BYTES the log serves and require it
# to equal the signed checkpoint root. Authenticating the root alone is not
# enough: /leaves is unauthenticated JSON, so the log (or the CDN terminating
# its TLS) could serve altered or omitted leaves under a consistent checkpoint
# and hide a watched append. This is the gap that broke CT's monitors; the
# fix is the one that caught the Yeti 2022 bit-flip.
def leaf_hash(data):
    return hashlib.sha256(b"\x00" + data).digest()


def fringe_append(fringe, leaf_h):
    """Fold one leaf hash into the fringe of perfect-subtree roots.

    fringe is a list of [count, hash] entries, left-to-right, with strictly
    decreasing counts (the powers of two in the binary length). Appending a
    leaf and carrying merges equal-sized right neighbours — binary increment.
    """
    node, size = leaf_h, 1
    while fringe and fringe[-1][0] == size:
        node = node_hash(fringe.pop()[1], node)
        size *= 2
    fringe.append([size, node])


def fringe_root(fringe):
    """RFC 6962 tree root from the fringe: MTH splits at the largest perfect
    left subtree, so fold the (decreasing-size) roots from the right."""
    if not fringe:
        return hashlib.sha256(b"").digest()
    acc = fringe[-1][1]
    for _size, h in reversed(fringe[:-1]):
        acc = node_hash(h, acc)
    return acc


def fringe_to_state(fringe):
    return [[c, base64.b64encode(h).decode()] for c, h in fringe]


def fringe_from_state(sf):
    return [[c, base64.b64decode(h)] for c, h in sf]


def fetch_range_leaf_hashes(start, end):
    """Fetch leaves [start,end) in <=256 batches; return (leaf_hashes, raws).
    Rejects a short/over-long batch — a mis-sized batch silently mis-indexes
    every later leaf, so it is treated as a fetch error by the caller."""
    hashes, raws = [], []
    for s in range(start, end, 256):
        e = min(s + 256, end)
        batch = json.loads(http_get(f"/leaves?start={s}&end={e}"))
        got = batch.get("leaves", [])
        if len(got) != e - s:
            raise ValueError(f"/leaves[{s}:{e}] returned {len(got)}, expected {e - s}")
        for b64leaf in got:
            raw = base64.b64decode(b64leaf)
            raws.append(raw)
            hashes.append(leaf_hash(raw))
    return hashes, raws


# ── alerts ────────────────────────────────────────────────────────────
def send_email(subject, text, to, dry):
    if dry:
        print(f"[dry-run] EMAIL to={to} subject={subject}\n{text}\n")
        return True
    try:
        return _send_email(subject, text, to)
    except Exception as e:
        log_line(f"email FAILED to={to} subject={subject!r} err={e}")
        return False


def _send_email(subject, text, to):
    key = [l.split("=", 1)[1].strip() for l in open(RESEND_ENV) if l.startswith("RESEND_API_KEY=")][0]
    payload = json.dumps({"from": FROM_EMAIL, "to": [to], "subject": subject, "text": text}).encode()
    req = urllib.request.Request(
        "https://api.resend.com/emails", data=payload, method="POST",
        headers={"Authorization": "Bearer " + key, "Content-Type": "application/json",
                 "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) markovian-monitor"})
    with urllib.request.urlopen(req, timeout=30) as r:
        ok = r.status in (200, 201)
    log_line(f"email sent to={to} subject={subject!r} ok={ok}")
    return ok


def log_line(msg):
    with open(os.path.join(BASE, "monitor.log"), "a") as f:
        f.write(f"{time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())} {msg}\n")


def save_state(state):
    """Atomic write with a .bak of the prior state — a crash mid-write must
    not corrupt state.json (a corrupt or missing file is treated as a hard
    stop next run, never a silent re-baseline)."""
    tmp = STATE_PATH + ".tmp"
    with open(tmp, "w") as f:
        json.dump(state, f)
        f.flush()
        os.fsync(f.fileno())
    if os.path.exists(STATE_PATH):
        import shutil
        shutil.copy2(STATE_PATH, STATE_PATH + ".bak")
    os.replace(tmp, STATE_PATH)


def leaf_matches(raw, issuer, w):
    """A watch hits if the issuer matches (case-insensitive on the parsed
    field) or the substring appears in EITHER the raw bytes or a normalized
    form. Substring-on-raw is evadable by JSON \\u-escaping / case / spacing
    (a published CT concealment attack), so we also match a canonicalized
    lowercased rendering of the parsed JSON."""
    mi = w.get("match_issuer")
    if mi and issuer is not None and issuer.lower() == mi.lower():
        return True
    ms = w.get("match_substring")
    if ms:
        needle = ms.lower().encode()
        if needle in raw.lower():
            return True
        try:
            canon = json.dumps(json.loads(raw), sort_keys=True, ensure_ascii=False).lower().encode()
            if needle in canon:
                return True
        except Exception:
            pass
    return False


# ── main ──────────────────────────────────────────────────────────────
def main():
    dry = "--dry-run" in sys.argv
    if "--once-test-email" in sys.argv:
        send_email("[markovian-monitor] test alert",
                   "Test alert from the log monitor on mkv-node-1. If you read this, the alert path works.",
                   ALERT_EMAIL, dry)
        return

    watches = json.load(open(WATCHES_PATH)) if os.path.exists(WATCHES_PATH) else []
    freshness_max = int(CONFIG.get("freshness_max_seconds", 10800))  # 3h; witnesses cosign hourly
    now = int(time.time())

    # ── state: corrupt or unexpectedly-missing is a HARD STOP, never a
    # silent re-baseline. A deleted state.json used to fall through to a
    # fresh baseline and permanently skip every leaf since. ──
    init = "--init" in sys.argv
    if os.path.exists(STATE_PATH):
        try:
            state = json.load(open(STATE_PATH))
        except Exception as e:
            log_line(f"state.json UNREADABLE ({e}) — refusing to run")
            send_email("[markovian-monitor] state unreadable",
                       f"state.json could not be parsed ({e}); the monitor is halted until a "
                       f"human restores it or re-inits deliberately. A .bak may exist beside it.",
                       ALERT_EMAIL, dry)
            return
    elif init:
        state = {}
    else:
        log_line("state.json MISSING and not --init — refusing to silently re-baseline")
        send_email("[markovian-monitor] state missing",
                   "state.json is missing and this run was not --init. Refusing to re-baseline "
                   "silently (that would skip every leaf appended since the last known head). "
                   "Investigate, then re-init deliberately if the loss is real.", ALERT_EMAIL, dry)
        return

    try:
        note = http_get("/checkpoint")
    except Exception as e:
        n = state.get("consecutive_failures", 0) + 1
        state["consecutive_failures"] = n
        log_line(f"checkpoint fetch FAILED ({e}) consecutive={n}")
        if n >= 3:  # re-alert every 3 while down, not once
            send_email("[markovian-monitor] log endpoint unreachable",
                       f"{n} consecutive hourly failures fetching {LOG_URL}/checkpoint. Last error: {e}", ALERT_EMAIL, dry)
        save_state(state)
        return
    state["consecutive_failures"] = 0

    body, origin, size, root, sigs = parse_checkpoint(note)
    problems = []

    sig_ok = verify_log_sig(body, sigs)
    if not sig_ok:
        problems.append("log signature INVALID on witnessed checkpoint")
    verified, invalid, unknown, skipped, newest_ts = verify_cosignatures(body, sigs)
    for name, reason in sorted(invalid):
        problems.append(f"witness cosignature INVALID: {name} ({reason})")
    if len(verified) < QUORUM_MIN:
        problems.append(f"verified witness cosignatures {len(verified)} < quorum_min {QUORUM_MIN}: "
                        f"verified={sorted(verified)}")
    # freshness: witnessing prevents equivocation, not withholding — a fully
    # authenticated but FROZEN checkpoint (stale CDN cache, or a log that
    # stopped) looks identical to "no new activity" forever unless we check.
    stale_by = now - newest_ts if newest_ts else None
    if newest_ts and stale_by > freshness_max:
        problems.append(f"checkpoint STALE: newest witness cosignature is {stale_by}s old "
                        f"(> {freshness_max}s) — log frozen or a cached view is being served")
    cosig_summary = (f"verified={len(verified)}/{len(WITNESS_VKEYS)} invalid={len(invalid)} "
                     f"unknown={sorted(unknown) if unknown else 0} pq_skipped={skipped} "
                     f"cosig_age={stale_by}s")
    authenticated = sig_ok and len(verified) >= QUORUM_MIN

    old_size = state.get("size", 0)
    old_root = base64.b64decode(state["root"]) if "root" in state else b""

    # ── bootstrap: build the Merkle fringe from ALL leaves and require it to
    # reproduce the checkpoint root before trusting anything. ──
    if init:
        if not authenticated:
            log_line(f"REFUSED to initialize: checkpoint unauthenticated ({cosig_summary})")
            for p in problems:
                send_email("[markovian-monitor] ALERT", p + f"\n\ncheckpoint size={size}", ALERT_EMAIL, dry)
            return
        try:
            hashes, _ = fetch_range_leaf_hashes(0, size)
        except Exception as e:
            log_line(f"init leaf fetch failed: {e}")
            send_email("[markovian-monitor] init failed", f"could not fetch leaves for init: {e}", ALERT_EMAIL, dry)
            return
        fr = []
        for h in hashes:
            fringe_append(fr, h)
        if fringe_root(fr) != root:
            log_line("REFUSED to initialize: leaf set does not reproduce checkpoint root")
            send_email("[markovian-monitor] init ALERT",
                       "the leaves the log served do NOT recompute to the signed checkpoint root at init; "
                       "not baselining.", ALERT_EMAIL, dry)
            return
        state.update({"size": size, "root": base64.b64encode(root).decode(),
                      "fringe": fringe_to_state(fr), "last_heartbeat": time.strftime("%Y-%m-%d", time.gmtime())})
        save_state(state)
        log_line(f"initialized at size={size} {cosig_summary} (leaf-root verified)")
        for p in problems:
            send_email("[markovian-monitor] ALERT", p + f"\n\ncheckpoint size={size}", ALERT_EMAIL, dry)
        return

    if size < old_size:
        problems.append(f"tree SHRANK: {old_size} -> {size} (rollback/fork)")
    elif size > old_size:
        proof_body = http_get(f"/consistency?old={old_size}&new={size}")
        proof = [base64.b64decode(l) for l in proof_body.decode().split() if l]
        if not verify_consistency(old_size, size, old_root, root, proof):
            problems.append(f"consistency proof FAILED {old_size}->{size} (fork or rewrite)")
    else:
        if root != old_root:
            problems.append(f"same size {size}, DIFFERENT root (equivocation)")

    tree_bad = any(("consistency" in p) or ("SHRANK" in p) or ("DIFFERENT root" in p) for p in problems)

    # ── send auth/consistency alerts NOW, before touching /leaves — a broken
    # or hostile /leaves endpoint must never be able to mute a fork alarm. ──
    for p in problems:
        send_email("[markovian-monitor] ALERT", p + f"\n\ncheckpoint size={size} origin={origin}", ALERT_EMAIL, dry)

    # ── leaf plane: fetch new leaves, recompute the root via the fringe, and
    # require it to equal the checkpoint root. Only a verified leaf set may
    # advance the head or be trusted for watch matching. ──
    matches = []
    leaf_verified = False
    fr = fringe_from_state(state["fringe"]) if "fringe" in state else None
    if authenticated and not tree_bad and size > old_size and fr is not None:
        try:
            hashes, raws = fetch_range_leaf_hashes(old_size, size)
            for h in hashes:
                fringe_append(fr, h)
            if fringe_root(fr) != root:
                problems.append(f"leaf set does NOT reproduce checkpoint root at size {size} "
                                f"(log served altered or omitted leaves)")
                send_email("[markovian-monitor] ALERT",
                           f"leaves {old_size}->{size} do not recompute to the signed root — "
                           f"the log or its CDN served a leaf set inconsistent with the committed tree.",
                           ALERT_EMAIL, dry)
            else:
                leaf_verified = True
                for j, raw in enumerate(raws):
                    issuer = None
                    try:
                        issuer = json.loads(raw).get("issuer")
                    except Exception:
                        pass
                    for w in watches:
                        if leaf_matches(raw, issuer, w):
                            matches.append((old_size + j, w, issuer))
        except Exception as e:
            problems.append(f"leaf fetch/verify error {old_size}->{size}: {e}")
            send_email("[markovian-monitor] ALERT",
                       f"leaf fetch or verification failed ({e}); head NOT advanced, range will be rechecked.",
                       ALERT_EMAIL, dry)
    elif authenticated and not tree_bad and size == old_size:
        leaf_verified = True  # nothing new; head already matches

    # one digest email per watch per run
    by_watch = {}
    for idx, w, issuer in matches:
        by_watch.setdefault(w["label"], (w, []))[1].append((idx, issuer))
    for label, (w, hits) in by_watch.items():
        to = w.get("email") or ALERT_EMAIL
        lines = [f"  leaf {idx}  issuer={issuer}  {LOG_URL}/inclusion?leaf={idx}&size={size}"
                 for idx, issuer in hits]
        send_email(f"[markovian-monitor] {len(hits)} new record(s) for watch: {label}",
                   f"Watch {label!r} matched {len(hits)} leaf/leaves appended since the last check "
                   f"(tree {old_size} -> {size}):\n\n" + "\n".join(lines) +
                   f"\n\nIf any of these appends was not yours, reply to this email.", to, dry)

    # ── advance the head only past a checkpoint that is authenticated,
    # consistent, AND whose leaves reproduce the committed root. ──
    if authenticated and not tree_bad and leaf_verified:
        state.update({"size": size, "root": base64.b64encode(root).decode(),
                      "fringe": fringe_to_state(fr) if fr is not None else state.get("fringe")})

    # ── daily heartbeat: silence must be a signal, not the absence of one.
    today = time.strftime("%Y-%m-%d", time.gmtime())
    if state.get("last_heartbeat") != today:
        ok = send_email("[markovian-monitor] daily heartbeat",
                        f"alive on mkv-node-1. head size={state.get('size')} {cosig_summary} "
                        f"last-run problems={len(problems)}. This is the once-a-day 'still watching' note.",
                        ALERT_EMAIL, dry)
        if ok:
            state["last_heartbeat"] = today

    save_state(state)
    log_line(f"ok size {old_size}->{size} {cosig_summary} leaf_verified={leaf_verified} "
             f"matches={len(matches)} problems={len(problems)}")


if __name__ == "__main__":
    main()
