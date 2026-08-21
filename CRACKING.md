# Cracking RDP Honeypot Captures

Commands tuned to the credential generator this honeypot actually observed,
ordered by measured return on GPU time. Benchmarked against 2,143 NetNTLMv2
hashes on an Apple M2 (Metal backend, 308 MH/s).

**Result: 82.1% recovered** — 1,761 of 2,143 — against 7% for plain rockyou.

Every hash is a separate password guess **and a separate salt**, so cost scales
with hash count as well as keyspace. 2,143 hashes means every candidate is hashed
2,143 times. Always attack `remaining_hashes.txt`, never the full set.

---

## The generator

Effectively every password observed fits one template with four slots:

```
[prefix] [stem] BaseWord [separator] digits [tail]
   @        Aa    Server        @      2026     #
```

| Slot | Observed values | Frequency |
|---|---|---|
| **BaseWord** | English words, forenames, football clubs, vendor names (`Cisco`, `Docker`, `Balena`), infrastructure terms (`Rdp`, `Server`, `Terminal`) | 490 confirmed |
| **separator** | none, `!`, `@`, occasionally `#$%._-*` | — |
| **digits** | `123456`, `123123`, `321`, `112233`, `0`, and a **year** (`2026`, also `1990`–`2010`) | 256 carry a year |
| **tail** | `@` (139), `!` (86), `$`, `.`, `*`, `!@#`, `!!` | 339 end in punctuation |
| **prefix** | `@`, `123`, `321`, `112233`, `123@` | 51 |
| **stem** | two letters before the digits: `Aa`, `Bb`, `Cc`, `Dd`, `Zz`, `Qu` | 27 stems |

88% start with a capital. Modal length 9.

The four constructions were not obvious up front — each was discovered by
inspecting what had already cracked. That process, not raw compute, produced
almost all of the yield.

---

## The ladder

Cheapest first. Each stage shrinks the salt count for the next.

### 0. Reuse what you already cracked

This botnet reuses passwords across targets and across days.

```bash
hashcat -m 5600 new_hashes.txt wordlists/cracked_passwords.txt
```

Measured: **+62 hashes in seconds** from a 199-word list.

### 1. Exhaust their vocabulary — highest yield per second

Small word list, huge rule set. Tiny keyspace, exhausts almost instantly.

```bash
hashcat -m 5600 new_hashes.txt wordlists/observed_bases.txt -r wordlists/generator_space.rule
```

Measured: **+189**, then **+135** after prefix rules were added. Best value in the
whole ladder — always run this before anything touching rockyou.

### 2. Generator rules over a real wordlist

```bash
head -1000000 rockyou.txt > rockyou1m.txt
hashcat -m 5600 new_hashes.txt rockyou1m.txt -r wordlists/generator_space.rule
```

Measured: **+350** on the top-1M pass.

Lighter alternative — `observed_suffixes.rule` is 727 rules vs 62,598:

```bash
hashcat -m 5600 new_hashes.txt rockyou.txt -r wordlists/observed_suffixes.rule
```

### 3. Masks

`observed.hcmask` holds the **19 shapes whose keyspace is tractable** (<= 5e11).
Frequency alone is a bad way to pick masks: the most common long shape,
`?u?l?l?l?l?l?l?l?l?d?d?d?d?d?d`, is 5.4e18 candidates and never finishes.

```bash
hashcat -m 5600 new_hashes.txt -a 3 wordlists/observed.hcmask
```

`--keyspace` does not work with mask files (hashcat limitation, not a syntax
error). Use `--runtime N` to time-box an exploratory run.

Individual high-value shapes:

```bash
hashcat -m 5600 new_hashes.txt -a 3 '?u?l?l?l?l?l?s?d?d?d'          # Word!321
hashcat -m 5600 new_hashes.txt -a 3 '?u?l?l?l?l?l?d?d?d?d?d?d'      # Word123456
hashcat -m 5600 new_hashes.txt -a 3 -1 '!@#$%._-' '?u?l?l?l?l?l?1?d?d?d'
```

### 4. Hybrid — low yield here, run last

```bash
hashcat -m 5600 new_hashes.txt -a 6 rockyou.txt '?d?d?d'
```

Measured **+6** where rules gave +189. The generator is rule-shaped, not
hybrid-shaped.

---

## What does NOT work

Recording the dead ends is as useful as the wins.

| Attack | Cost | Yield |
|---|---|---|
| rockyou + 30,000 generic rules | hours | +5 |
| Brute force a-z 1-6 (321M candidates) | 20 min | **2 real passwords** |
| 370k English dictionary x 727 suffix rules | 12 min | **1** |
| 10k-most-common straight | seconds | +3 |

The English-dictionary result is the most informative failure. A comprehensive
English word list crossed with confirmed suffix patterns should have gutted the
residue if those were ordinary words. It found one. **The remaining hashes are
not English words** — they are non-English terms, names, brands, transliterations
or random strings, and no amount of extra rules will reach them.

---

## Working with community cracks

Others may crack the same captures. Merging is worth it — but verify provenance
first, by hash rather than by trust.

```bash
# do their hashes belong to your capture at all?
cut -d: -f1-6 theirs.txt | sort -u > /tmp/theirs.txt
comm -12 /tmp/theirs.txt <(sort -u all_hashes.txt) | wc -l    # matches
comm -23 /tmp/theirs.txt <(sort -u all_hashes.txt) | wc -l    # foreign
```

A NetNTLMv2 blob carries a per-connection timestamp and nonce, so identical full
hashes can only mean identical captures. Matching NTProofStr alone is weaker.

If the file is plain passwords with no hashes, verify empirically — run them and
see what cracks:

```bash
hashcat -m 5600 remaining_hashes.txt theirs.txt
```

Then merge and rebuild the model, because their vocabulary crossed with your
suffix space covers ground neither list had alone:

```bash
cat theirs.txt >> honeypot.pot && sort -u honeypot.pot -o honeypot.pot
hashcat -m 5600 remaining_hashes.txt theirs_passwords.txt -r wordlists/generator_space.rule
```

**Every external batch taught us a structural gap**, not just extra rows:

| Batch | Revealed |
|---|---|
| own cracking | `word + sep + digits` |
| HoneyCracked #1 | two-letter stems, bare years |
| HoneyCracked #2 | trailing punctuation (+156 hashes) |
| Tib3rius | prefixes (+135 hashes) |

Always re-derive the rules after a merge — that is where the gain is.

---

## Feeding results back

```bash
hashcat -m 5600 hashes.txt --show > cracked.txt
python analyze_captures.py honeypot.db --import-cracked cracked.txt
```

This joins recovered passwords onto source IP, timestamp and client fingerprint —
who guessed what, and when — rather than leaving a detached list. It also reports
what is still uncracked, which is usually the more interesting column.

To regenerate the model files after new cracks, rebuild `observed_bases.txt`,
`observed_suffixes.txt` and the rule files from `cracked_passwords.txt`; the four
slots above are the structure to extract.

---

## Practical notes

**Do not query a potfile a running job is writing.** hashcat reports
`Separator unmatched` against the *hash* file, which sends you debugging the wrong
thing. I lost time to this twice. Snapshot instead:

```bash
cp honeypot.pot snap.pot
awk -F: 'NF-1==6' snap.pot > snap_clean.pot     # drop partial writes
hashcat -m 5600 hashes.txt --potfile-path snap_clean.pot --show
```

**hashcat uppercases the username** in `--show`, because NTLMv2 uppercases it
inside the HMAC. Match on the NTProofStr (field 5), never the whole string.
`--import-cracked` already does this.

**Lowercase dictionaries need case rules.** 88% of these passwords start with a
capital. A rule file of bare `$1$2$3` appends produces `server123`, never
`Server123`, and silently misses most of the target. All shipped rule files carry
`c`/`u`/`l` variants.

**Track what is left.** `--left` writes the uncracked hashes in the same format:

```bash
hashcat -m 5600 all_hashes.txt --left > remaining_hashes.txt
```

`--keyspace` takes attack parameters only — passing a hash file makes it fail with
a usage error that looks like a file problem.

**Cut the salt count for triage.** One hash per account answers "does anything
obvious fall?" quickly:

```bash
sort -u -t: -k1,2 netntlmv2.txt > sample.txt
```

**Long runs.** Use sessions so a stop is not a restart:

```bash
hashcat -m 5600 --session hp new_hashes.txt rockyou.txt -r wordlists/generator_space.rule
hashcat --session hp --restore
```

**Modes.** NetNTLMv2 is `-m 5600`, NetNTLMv1 is `-m 5500`. Never mix them in one
file — `analyze_captures.py --export-dir` splits them automatically.

**Apple Silicon** uses Metal automatically (`hashcat -I` to confirm). hashcat has
no Windows ARM64 build and needs an OpenCL/CUDA device, so crack on a GPU host,
not the honeypot VM.

---

## Files

| File | Contents |
|---|---|
| `wordlists/cracked_passwords.txt` | 1,559 confirmed passwords |
| `wordlists/password_prevalence.tsv` | the same, ranked by attempt count |
| `wordlists/observed_bases.txt` | 490 base words, suffix stripped |
| `wordlists/generator_space.rule` | 62,598 rules — the full four-slot model |
| `wordlists/observed_suffixes.rule` | 727 rules — observed suffixes only, case-aware |
| `wordlists/observed.hcmask` | 19 tractable mask shapes |
| `wordlists/remaining_hashes.txt` | still uncracked, ready to attack |

## Handling

These are other people's credentials — bots replay what they stole elsewhere.
Crack them to measure your own exposure, never to reuse. Keep the outputs
access-restricted and do not publish them raw.
