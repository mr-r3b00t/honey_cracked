# Cracking RDP Honeypot Captures

Commands tuned to the credential generator this honeypot actually observed, ordered
by return on GPU time. Measured against 2,143 NetNTLMv2 hashes on an Apple M2
(Metal backend).

Every hash is a **separate password guess** and a **separate salt**, so cost scales
with hash count as well as keyspace. A candidate is hashed once per hash in the
file — 2,143 hashes means 2,143× the work of a single one.

---

## The pattern

Effectively every password observed is:

```
<BaseWord><separator?><digits>
```

- **Base word** — capitalised English word, forename, football club, vendor name
  (`Cisco`, `Docker`, `Balena`), or infrastructure term (`Rdp`, `Server`, `Terminal`)
- **Separator** — usually none, `!`, `@`, occasionally `#$%._-*`
- **Digits** — `123456`, `123123`, `!321`, `@123`, `0`, `112233`, and a **year**
  component (`@2026`) that rolls over annually

Straight rockyou recovers about **7%**. Modelling the generator recovers **46%+**.

---

## 0. Reuse what you already cracked

Cheapest possible run. This botnet reuses passwords across targets, so a list built
from yesterday's capture cracks a meaningful slice of today's in seconds.

```bash
hashcat -m 5600 new_hashes.txt wordlists/cracked_passwords.txt
```

Measured: **62 hashes in seconds** from an 199-word list.

Then the same list run through the pattern rules, to catch the same base words
carrying different suffixes:

```bash
hashcat -m 5600 new_hashes.txt wordlists/cracked_passwords.txt -r wordlists/generator_space.rule
```

---

## 1. Exhaust their vocabulary — the highest-yield stage

The base words are a small, stable set. Crossing them with every plausible suffix is
a tiny keyspace that can be exhausted almost instantly.

```bash
hashcat -m 5600 new_hashes.txt wordlists/observed_bases.txt -r wordlists/generator_space.rule
```

Measured: **+189 hashes**, 123 words × 1,452 rules. Best value in the whole ladder —
run this before anything involving rockyou.

---

## 2. Generator rules over a real wordlist

Same rules, broader vocabulary. This is where most of the volume comes from.

```bash
# top 1M rockyou - fast, most of the yield
head -1000000 rockyou.txt > rockyou1m.txt
hashcat -m 5600 new_hashes.txt rockyou1m.txt -r wordlists/generator_space.rule

# full rockyou - slower, diminishing returns
hashcat -m 5600 new_hashes.txt rockyou.txt -r wordlists/generator_space.rule
```

Measured: **+350 hashes and climbing** on the top-1M pass alone.

For a lighter version, `observed_suffixes.rule` holds only the suffixes actually
seen (27 rules vs 1,452):

```bash
hashcat -m 5600 new_hashes.txt rockyou.txt -r wordlists/observed_suffixes.rule
```

---

## 3. Masks — when you want shapes, not words

127 distinct shapes cover the whole set; the top 22 cover 64%. `observed.hcmask`
holds the **19 shapes whose keyspace is actually tractable** (<= 5e11 candidates).
The frequent shapes are not all cheap — `?u?l?l?l?l?l?l?l?l?d?d?d?d?d?d` is 5.4e18
candidates, which is a pure-mask attack you will never finish. Those long shapes are
better reached with rules over a wordlist (stages 1-2), which is why masks sit at
stage 3 rather than the top.

```bash
hashcat -m 5600 new_hashes.txt -a 3 wordlists/observed.hcmask
```

Note: `--keyspace` does not work with mask files (hashcat limitation, not a syntax
error). Use `--runtime N` to time-box an exploratory mask run instead.

Individual high-value shapes:

```bash
# Word!321 / Word@123  - the single most common shape (7.7%)
hashcat -m 5600 new_hashes.txt -a 3 '?u?l?l?l?l?l?s?d?d?d'

# Word123456 (6.5%)
hashcat -m 5600 new_hashes.txt -a 3 '?u?l?l?l?l?l?d?d?d?d?d?d'

# Name0  - forename plus a single digit
hashcat -m 5600 new_hashes.txt -a 3 '?u?l?l?l?l?l?d'
```

Constrain the charset to make masks dramatically cheaper — the separators are only
ever a handful of characters:

```bash
hashcat -m 5600 new_hashes.txt -a 3 -1 '!@#$%._-' '?u?l?l?l?l?l?1?d?d?d'
```

---

## 4. Hybrid — wordlist plus appended digits

Useful when the base word is real but the suffix is not in the rules.

```bash
hashcat -m 5600 new_hashes.txt -a 6 rockyou.txt '?d?d?d'      # word + 3 digits
hashcat -m 5600 new_hashes.txt -a 6 rockyou.txt '?d?d?d?d?d?d'  # word + 6 digits

# separator then digits
hashcat -m 5600 new_hashes.txt -a 6 -1 '!@#' rockyou.txt '?1?d?d?d'
```

Lower yield than rules for this generator — measured **+6** where the rules gave
+189. Use it only after the rule stages.

---

## 5. Year rollover

The `@2026` component is dated. In January, regenerate the rules or add the new year
directly:

```bash
printf '$@$2$0$2$7\nc $@$2$0$2$7\n$!$2$0$2$7\n$2$0$2$7\n' > year2027.rule
hashcat -m 5600 new_hashes.txt rockyou.txt -r year2027.rule
```

`generator_space.rule` already covers **2023–2028**, so it stays valid without edits.

---

## Running it as a ladder

Cheapest first, so the expensive stages face fewer uncracked hashes:

```bash
#!/bin/bash
H=new_hashes.txt; W=wordlists; P=./honeypot.pot
run(){ hashcat -m 5600 -a "$1" "$H" "${@:2}" --potfile-path "$P" --quiet --force; }

run 0 "$W/cracked_passwords.txt"
run 0 "$W/observed_bases.txt"     -r "$W/generator_space.rule"
run 0 "$W/cracked_passwords.txt"  -r "$W/generator_space.rule"
run 0 rockyou1m.txt               -r "$W/generator_space.rule"
run 3 "$W/observed.hcmask"
run 0 rockyou.txt                 -r "$W/observed_suffixes.rule"
run 0 rockyou.txt
hashcat -m 5600 "$H" --potfile-path "$P" --show
```

---

## Practical notes

**Reading results.** `--show` reads the potfile; re-running it is free.

```bash
hashcat -m 5600 new_hashes.txt --show
hashcat -m 5600 new_hashes.txt --show | awk -F: '{print $NF}' | sort -u > passwords.txt
```

**Do not query a potfile a running job is writing.** hashcat reports
`Separator unmatched` against the *hash* file, which sends you debugging the wrong
thing. Snapshot it instead:

```bash
cp honeypot.pot snap.pot
hashcat -m 5600 new_hashes.txt --potfile-path snap.pot --show
```

**hashcat uppercases the username** in `--show` output, because NTLMv2 uppercases it
inside the HMAC. Match on the NTProofStr (field 5), not the whole string —
`analyze_captures.py --import-cracked` already does this.

**Cut the salt count for a fast triage pass.** One hash per account answers "does
anything obvious fall?" in a fraction of the time:

```bash
sort -u -t: -k1,2 netntlmv2.txt > sample.txt
```

**Long runs.** Use sessions so a stop is not a restart:

```bash
hashcat -m 5600 --session hp3 new_hashes.txt rockyou.txt -r wordlists/generator_space.rule
hashcat --session hp3 --restore
```

**Modes.** NetNTLMv2 is `-m 5600`, NetNTLMv1 is `-m 5500`. Never mix them in one file.

**Apple Silicon** uses the Metal backend automatically; check with `hashcat -I`.
hashcat has no Windows ARM64 build and needs an OpenCL/CUDA device, so crack on a
GPU host rather than the honeypot VM.

---

## Handling

These are other people's credentials — bots replay what they stole elsewhere.
Crack them to measure your own exposure, never to reuse. Keep the outputs
access-restricted and do not publish them raw.
