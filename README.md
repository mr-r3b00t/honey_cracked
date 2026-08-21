# RDP Credential Honeypot

A listener that speaks enough of the RDP protocol (MS-RDPBCGR) to reach the point
where a connecting client hands over its credentials, logs them, and authenticates
nothing. Built to answer a question Windows itself cannot: **what passwords are
they actually guessing?**

Event ID 4625 gives you the username, the source IP and a failure code. It never
gives you the attempted password — LSA consumes the plaintext during
authentication and never exposes it to any audit surface. The only way to see it
is to be the server.

> **Defensive use only.** Run this on a disposable, non-domain-joined host you
> own. See [Handling what you collect](#handling-what-you-collect).

---

## Contents

| File | Purpose |
|---|---|
| `rdp_honeypot.py` | The listener. Standard library only. |
| `analyze_captures.py` | Reporting and export. |
| `Install-RdpHoneypot.ps1` | Windows deployment and diagnostics. |
| `CRACKING.md` | Cracking runbook, tuned to the observed generator. |
| `wordlists/` | The attacker model: confirmed passwords, base words, hashcat rules. |

## Requirements

Python 3.8+. **That is the entire dependency list** — RC4, RSA key generation, the
MS-RDPBCGR key schedule, DER/PER encoding, X.509 certificate minting and the NTLM
messages are all implemented in `rdp_honeypot.py`. No wheels, no compiler, works
on x64 and ARM64 Windows alike.

If `cryptography` or an `openssl` binary happens to be installed it will use them
as a faster path for generating the TLS certificate. Neither is required.

---

## How it works

RDP carries credentials in three different places depending on which security
layer gets negotiated. Two of them yield plaintext; one does not.

```
                    client's X.224 Connection Request
                                  |
                      honeypot picks the response
                    /             |             \
          PROTOCOL_SSL     PROTOCOL_RDP      PROTOCOL_HYBRID
         (TLS, no NLA)     (legacy RC4)       (CredSSP/NLA)
                    \             /                 |
                Client Info PDU (TS_INFO_PACKET)  NTLM type 3
                            |                       |
                  PLAINTEXT PASSWORD           NetNTLMv2 hash
```

- **TLS path** — the honeypot answers `PROTOCOL_SSL`, so authentication happens at
  the RDP layer inside the tunnel and the Client Info PDU arrives unencrypted.
- **Legacy path** — the honeypot hands the client an RSA key in a Proprietary
  Server Certificate, decrypts the client random from the Security Exchange PDU,
  derives the session keys per MS-RDPBCGR 5.3.5, and RC4-decrypts the credential PDU.
- **NLA** — under CredSSP the password never leaves the client as plaintext, so
  this path yields a crackable NetNTLMv2 hash instead. It is used only as a
  fallback (see [`--nla`](#nla-modes)).

Nothing is ever forwarded to a real host. This is a sinkhole, not a
man-in-the-middle: the connection is closed once the credential is recorded.

---

## Install (Windows)

### 1. Install Python machine-wide

```powershell
winget install Python.Python.3.12 --scope machine
```

**This matters.** A per-user install under `C:\Users\<name>\AppData\...` cannot be
executed by the service account the scheduled task runs as, and Task Scheduler
fails with `2147942405` (`0x80070005`, ACCESS_DENIED) before your script ever runs.

### 2. Deploy

From the directory containing the scripts, elevated:

```powershell
.\Install-RdpHoneypot.ps1 -Stage -DisableRealRdp -AllowFirewall -InstallTask
```

Or to keep real RDP available, moved to another port and locked to your subnet:

```powershell
.\Install-RdpHoneypot.ps1 -Stage -MoveRealRdp 3390 -RestrictAdminPort 10.0.0.0/24 `
                          -AllowFirewall -InstallTask
```

If you move the real listener, **reconnect on the new port before logging off.**

The installer verifies the result rather than assuming it: after registering the
task it polls for the listening socket and reports the decoded error plus the log
tail if nothing binds.

### Installer switches

| Switch | Effect |
|---|---|
| `-Diagnose` | Report why an install is not running, then exit. Start here when something is wrong. |
| `-Stage` | Copy the scripts to `-InstallDir` (default `C:\RdpHoneypot`). Required if they currently sit in a user profile. |
| `-DisableRealRdp` | Turn the genuine RDP listener off entirely. |
| `-MoveRealRdp <port>` | Move the genuine RDP listener to another port. |
| `-RestrictAdminPort <cidr>` | Limit that moved port to a management range. |
| `-AllowFirewall` | Open inbound TCP/3389. |
| `-InstallTask` | Register the boot-time scheduled task. |
| `-GrantPythonAccess` | Last resort: grant the service account read+execute on a per-user Python instead of reinstalling it. Opens part of that profile. |
| `-InstallDir` | Default `C:\RdpHoneypot`. |
| `-RunAsUser` | Default `NT AUTHORITY\LOCAL SERVICE`. |
| `-Port` | Default `3389`. |

Do **not** run the task as `SYSTEM`. `LOCAL SERVICE` is the correct principal for
an internet-facing listener; binding port 3389 needs no special privilege on Windows.

### Manual run

```powershell
python C:\RdpHoneypot\rdp_honeypot.py --port 3389 --outdir C:\RdpHoneypot\captures `
       --log C:\RdpHoneypot\captures\honeypot.log
```

```bash
python3 rdp_honeypot.py --port 3389 --outdir ./captures
```

---

## Usage

### Listener options

| Option | Default | Meaning |
|---|---|---|
| `--bind` | `0.0.0.0` | Listen address. |
| `--port` | `3389` | Listen port. |
| `--outdir` | `captures` | Database, JSONL, TLS certificate and log. |
| `--log` | *(none)* | Also append console output to this file. |
| `--mode` | `auto` | `auto` prefers TLS and falls back to legacy RDP. `tls` / `rdp` force one. |
| `--nla` | `auto` | See below. |
| `--nla-escalate` | `20` | In `auto` mode, after N downgrade refusals with zero plaintext won, offer NLA to every source. `0` disables. |
| `--max-conns` | `200` | Concurrent connection cap. |

### NLA modes

| Mode | Behaviour |
|---|---|
| `auto` **(recommended)** | Offer the downgrade first for plaintext. Sources that refuse are remembered — persisted across restarts, keyed on the `/24` as well as the exact IP — and offered NLA next time. If `--nla-escalate` refusals accumulate without a single plaintext win, stop trying to downgrade and take hashes from everyone. |
| `capture` | Always accept NLA when offered. **Yields hashes instead of plaintext** — only use this if you specifically want hashes. |
| `refuse` | Never offer NLA. Maximum plaintext, but single-shot scanners that require NLA are lost entirely. |

Plaintext is strictly more useful than a hash you have to crack, so `auto` is the
right default — but it only pays off if a refusing source comes back. Real botnets
rotate addresses and move on, which is why `auto` escalates rather than bleeding
sources indefinitely. **If you see a pile of `nla_downgrade_refused` and zero
captures, that is the escalation threshold not yet reached** — lower it, or switch
to `--nla capture`.

If you are getting hashes and no passwords, check this setting:

```powershell
(Get-ScheduledTask RdpHoneypot).Actions[0].Arguments
```

### Verify it is running

```powershell
Get-NetTCPConnection -LocalPort 3389 -State Listen
Get-Content C:\RdpHoneypot\captures\honeypot.log -Tail 20 -Wait
```

A capture looks like this:

```
[2026-08-20T16:05:33.223Z] CAPTURE 203.0.113.9:51022 [tls/none] CORP\'jsmith' : 'Summer2026!' (client='B_309' build=18363)
[2026-08-20T16:08:41.550Z] NETNTLM 198.51.100.4:44119 [NetNTLMv2] CORP\'Administrator' (workstation='WIN-BMK739Q7BDC')
```

---

## Analysis

```powershell
python C:\RdpHoneypot\analyze_captures.py C:\RdpHoneypot\captures\honeypot.db
```

Reports top passwords, username:password pairs, password composition and length,
password *shapes* (`Password123!` → `ulllllllldddds`), per-source behaviour,
client fingerprints and session outcomes.

### Check against your real accounts

The operationally important one — pass your actual account names and it reports
every password guessed against them:

```powershell
python C:\RdpHoneypot\analyze_captures.py C:\RdpHoneypot\captures\honeypot.db `
       --check-users Administrator guest svc_backup
```

If any guess is a password actually in use, treat that account as compromised.

### Analyzer options

| Option | Meaning |
|---|---|
| `--version` | Print version and resolved path. Use this to confirm which copy you are running. |
| `--top N` | Rows per table (default 20). |
| `--check-users A B C` | Report guesses aimed at these real account names. |
| `--export-dir DIR` | Write the full intel bundle. |
| `--export-hashes FILE` | Hashes only. v1 and v2 are written to separate files. |
| `--import-cracked FILE` | Read a hashcat potfile (or `--show` output) and join recovered passwords back onto the capture metadata. |
| `--since ISO_TS` | Only rows at or after this timestamp, for incremental pulls. |

---

## Export

```powershell
python C:\RdpHoneypot\analyze_captures.py C:\RdpHoneypot\captures\honeypot.db `
       --export-dir C:\RdpHoneypot\export
```

| File | Contents |
|---|---|
| `usernames.txt` | Every username seen, frequency-ranked. Merged across both capture paths. |
| `usernames.csv` | The same with attempt counts, source-IP counts, first/last seen. |
| `passwords.txt` | Distinct plaintext passwords, frequency-ranked. |
| `credentials.txt` | `username:password` pairs. |
| `credentials.csv` | One row per capture with source IP and client fingerprint. |
| `netntlmv2.txt` | Hashes for `hashcat -m 5600`. |
| `netntlmv1.txt` | Hashes for `hashcat -m 5500`. Only written if any v1 appears. |
| `source_ips.txt` | Every source IP, most active first. Firewall/SIEM ready. |
| `MANIFEST.txt` | What each file is, plus the cracking commands. |

v1 and v2 are **always** written separately — they are different hashcat modes and
a mixed file will not parse.

### Incremental pulls

```powershell
python C:\RdpHoneypot\analyze_captures.py C:\RdpHoneypot\captures\honeypot.db `
       --export-dir C:\RdpHoneypot\export\daily --since 2026-08-20T00:00:00Z
```

`captures.jsonl` is append-only and already structured, if you would rather tail
it straight into a log shipper.

---

## Feeding cracked passwords back

Cracking leaves the plaintext in hashcat's potfile and the metadata in SQLite,
with nothing joining them. `--import-cracked` closes that loop:

```bash
hashcat -m 5600 netntlmv2.txt --show > cracked.txt
python analyze_captures.py honeypot.db --import-cracked cracked.txt
```

It reports which source IP guessed which password and when, plus what is still
uncracked. Matching is on the NTProofStr rather than the raw hash string, because
hashcat uppercases the username in its output.

## Cracking

See **[CRACKING.md](CRACKING.md)** for the full runbook. The attacker's password
generator has been reverse-engineered from these captures, and the rule files in
`wordlists/` reproduce it — taking recovery from 7% (plain rockyou) to **82%**.

```bash
# fastest first pass against a new capture
hashcat -m 5600 new_hashes.txt wordlists/cracked_passwords.txt
hashcat -m 5600 new_hashes.txt wordlists/observed_bases.txt -r wordlists/generator_space.rule
```

```bash
hashcat -m 5600 netntlmv2.txt rockyou.txt
hashcat -m 5600 netntlmv2.txt --show
```

**Every hash is a distinct password guess**, not one account repeated — so
cracking N hashes recovers N of their guesses. Each is also a separate salt, so
cracking time scales with hash count, not just wordlist size. On a busy honeypot
that file grows fast; for a quick "which accounts fall to rockyou" pass, reduce
to one hash per account first:

```bash
sort -u -t: -k1,2 netntlmv2.txt > sample.txt
```

Notes on tooling:

- **hashcat is not in winget.** Use `choco install hashcat`, or the 7z from hashcat.net.
- **hashcat has no Windows ARM64 build** and needs an OpenCL/CUDA backend. On an
  ARM64 VM it will most likely find no usable device. Crack on a machine with a
  real GPU — on Apple Silicon, `brew install hashcat` uses the Metal backend.

---

## Output

`--outdir` contains:

```
honeypot.db       SQLite: captures, netntlm, sessions
captures.jsonl    append-only mirror, one JSON object per event
honeypot.log      console log (with --log)
nla_refused.txt   sources that refused a downgrade, persisted across restarts
server.crt/.key   self-signed TLS certificate, generated on first run
```

### The attacker model (`wordlists/`)

Derived from 2,143 captured hashes, 82% of which have been cracked.

| File | Contents |
|---|---|
| `cracked_passwords.txt` | 1,559 confirmed passwords |
| `password_prevalence.tsv` | the same, ranked by attempt count |
| `observed_bases.txt` | 490 base words with suffixes stripped |
| `generator_space.rule` | 62,598 rules reproducing their password generator |
| `observed_suffixes.rule` | 727 rules - observed suffixes only, case-aware |
| `observed.hcmask` | 19 tractable mask shapes |
| `remaining_hashes.txt` | still uncracked, ready for the next attempt |

Their generator is `[prefix][stem]Word[separator]digits[tail]` - see
[CRACKING.md](CRACKING.md). The rules cover years 1990-2010 and 2023-2028, so they
survive the annual rollover without edits.

### Schema

**`captures`** — plaintext credentials
`ts, src_ip, src_port, transport, selected_protocol, requested_protocols,
encryption, domain, username, password, password_len, cookie, client_name,
client_build, client_product_id, keyboard_layout, client_address,
alternate_shell, desktop, channels, duration_ms`

**`netntlm`** — hashes from NLA sources
`ts, src_ip, src_port, domain, username, workstation, hash_format, hash, duration_ms`

**`sessions`** — connections that did *not* yield a credential, and why
`ts, src_ip, src_port, outcome, requested_protocols, cookie, detail, duration_ms`

Outcomes include `nla_downgrade_refused`, `nla_no_authenticate`, `incomplete` and
`error`. A high `nla_downgrade_refused` count with no captures means your attacker
population requires NLA — see [NLA modes](#nla-modes). Watch this table — it is how you spot a bot population your configuration
is missing.

`client_name` is worth particular attention: it is the same value that appears as
`WorkstationName` in Event 4625, so captures correlate directly with your event
log analysis.

---

## Troubleshooting

Start here:

```powershell
.\Install-RdpHoneypot.ps1 -Diagnose
```

| Symptom | Cause | Fix |
|---|---|---|
| Task Scheduler error `2147942405` / `0x80070005` | Per-user Python; the service account cannot execute it | Install Python `--scope machine`, or `-GrantPythonAccess` |
| `unrecognized arguments: --export-dir` | Running an older `analyze_captures.py` | Check `--version`, then copy the current file over |
| Task runs but nothing listens on 3389 | Real RDP still owns the port | `-DisableRealRdp` or `-MoveRealRdp` |
| Hashes but no plaintext passwords | Running `--nla capture` | Re-register with `--nla auto` |
| Many `nla_downgrade_refused`, no captures at all | Attackers require NLA and never revisit, so `auto` never converts | Lower `--nla-escalate` (try 5) or use `--nla capture` |
| Connections logged as `incomplete` only | Port scanners, not RDP clients | Normal. Check `sessions.detail` |
| No TLS, legacy RDP only | Certificate generation failed | Check the startup log; the built-in generator needs no dependencies |

---

## Handling what you collect

**Captured passwords are other people's credentials.** Brute-force bots replay
credentials harvested from breaches elsewhere, so `passwords.txt` and
`credentials.*` will contain real passwords belonging to third parties who have
nothing to do with you.

- Restrict access to the capture files. Do not publish them raw.
- Never test a captured credential against any system that is not yours.
- Crack the hashes only to measure your own exposure.
- Retention may touch data-protection obligations depending on your jurisdiction.

**The host itself accepts weak and legacy RDP security by design.** Keep it
standalone, non-domain-joined, egress-restricted, holding no credentials you care
about and sharing no local admin password with anything else. The installer warns
and requires confirmation if it detects a domain-joined machine.

---

## Limitations

- Clients that require NLA and never reconnect yield nothing on their first visit
  and a hash on their second. Some single-shot scanners are missed entirely.
- The password behind a NetNTLMv2 hash is only recoverable by cracking it.
- This is a sinkhole — nobody ever gets a session, so you learn what attackers
  guess, not what they would do. To observe the session itself you need a proxying
  honeypot such as [PyRDP](https://github.com/GoSecure/pyrdp), which forwards to a
  sacrificial host.
- `IpPort` is not recorded by RDP at this stage, and source IPs are rented
  infrastructure — neither supports attribution.

---

## Tested

Verified end to end against FreeRDP 3.30.0:

- Plaintext captured on both the TLS and legacy RC4 paths, including non-ASCII
  (`Sömmer2026!£`) and empty passwords
- Client hostname, build and keyboard layout recovered
- Adaptive NLA: first connection logs `nla_downgrade_refused`, second yields a hash
- Captured NetNTLMv2 verified by recomputing NTProofStr from the known plaintext,
  then cracked with real `hashcat -m 5600` — 4/4 recovered from the export
- Certificate generated with no `cryptography` and no `openssl` present; OpenSSL
  confirms valid X.509 v3, self-signature verifies, key modulus matches
- HTTP requests, random bytes, malformed TPKT lengths, stray TLS hellos and empty
  connections all logged without crashing the listener
- NLA policy unit-tested: escalation threshold, `/24` inheritance, suppression
  while downgrading is winning, persistence across restart, `0` disabling
  escalation, and IPv6 sources
