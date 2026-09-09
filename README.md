# log-monitor

A standing monitor for a [C2SP](https://c2sp.org)-checkpoint transparency log. It runs on a
schedule, from a machine separate from the log, and reads only the log's public endpoints.

Each run it:

1. Fetches the witnessed checkpoint and verifies the log's Ed25519 signature over the signed note.
2. Verifies each witness cosignature ([tlog-cosignature](https://c2sp.org/tlog-cosignature),
   `cosignature/v1`) against a pinned key. Quorum counts only cosignatures that verify; a pinned
   witness whose cosignature fails to verify is its own alert. ML-DSA-44 cosignature lines are
   verified too, against the keys in `pq_vkeys`, but they do not count toward the quorum.
3. Verifies an [RFC 6962](https://www.rfc-editor.org/rfc/rfc6962) consistency proof from the last
   trusted head to the new one.
4. **Recomputes the tree root from the leaf bytes the log serves**, and requires it to equal the
   signed head. Authenticating the head alone is not enough: the leaf endpoint is unauthenticated,
   so a log — or a CDN in front of it — could serve an altered or omitted leaf under a valid head.
   This is the check that catches that class of failure.
5. Matches the verified leaves against a list of watched identities and emails a digest for hits.

The trusted head advances only past a checkpoint that is signed, cosigned to quorum, consistent,
and whose leaves reproduce the head. Any failure leaves the head unchanged and re-alerts. It also
alerts on a stale (frozen) checkpoint and sends a daily heartbeat, so silence is itself a signal.

## What it verifies, and what it does not

- Verified: the log signature, each pinned Ed25519 witness cosignature, each ML-DSA-44
  cosignature, append-only consistency, and that the served leaves reproduce the committed root.
- The quorum is counted over verified Ed25519 cosignatures from pinned witnesses alone. A valid
  ML-DSA-44 line cannot stand in for a missing witness, and neither can an advisory one.
- ML-DSA-44 verification uses every implementation it can import — `mldsa` and `dilithium_py` —
  and they must agree. Disagreement is recorded as invalid, never as a pass. With neither
  installed the run reports the lines as *could not check*; it does not pass them silently.
  Prefer `mldsa`: `dilithium_py`'s own README says it is an educational resource that should not
  be used for cryptographic applications, which is a thin foundation for the only check standing
  behind a published key.
- A watch match means the bytes matched. It says nothing about whether a record's content is true.

## Advisory witnesses

A log can be cosigned by a witness that is not in its pinned set. `witness_vkeys_advisory` holds
keys for exactly that case: the cosignature is verified and reported, an invalid one alerts like
any other, and it never counts toward the quorum. This keeps the monitor's arithmetic equal to the
log's published policy while still checking the extra signature, so a reader who counts more
cosignature lines than pinned keys can see why.

Moving a key from advisory to pinned is a trust decision, not a config convenience: for the
Markovian log it requires a new signed trust-root manifest.

## Run it

Requires Python 3 and the `cryptography` package. Install `mldsa` to verify ML-DSA-44
cosignatures, and `dilithium_py` alongside it if you want two implementations cross-checking
each other; with neither, those lines are reported as unchecked.

```
cp config.example.json config.json      # already points at markovianprotocol.com's log
cp watches.example.json watches.json    # edit to watch your own identities
python3 monitor.py --init               # baseline at the current head (verifies leaves→root)
python3 monitor.py                       # one pass; put this on an hourly cron
```

Flags: `--dry-run` prints alerts instead of sending them; `--init` establishes the baseline (it
refuses to baseline an unauthenticated checkpoint); `--once-test-email` sends one test alert.
Email goes through [Resend](https://resend.com) — point `resend_env` at a file with a
`RESEND_API_KEY=` line, or use `--dry-run` and wire your own channel.

`config.example.json` is preconfigured for the Markovian Protocol log: its log key, its seven
pinned witness keys as published at
[`/.well-known/verify_checkpoint.py`](https://markovianprotocol.com/.well-known/verify_checkpoint.py),
the one advisory witness that cosigns without being pinned, and the ML-DSA-44 keys. Point it at any
C2SP-checkpoint log by replacing `log_url`, `log_vkey`, and `witness_vkeys`.

## Why a separate monitor

A tamper-evident log proves nothing on its own; the proof exists only when someone verifies it.
Witnesses check the log as it writes and refuse to cosign a fork. A monitor checks what the log
later serves to readers, which the witnesses never see. The two cover different sides of the same
log. Running your own copy against a log you rely on, and comparing heads with others, is the
point — the design is standard, and this is one small implementation of it.

Apache-2.0.
