# Password entropy model (assumptions are part of the result)

Entropy here is an **estimate of guessing cost under a simple attacker model**, not a proof of strength.

1. **Naive entropy** = `length × log2(pool)`, pool = sum of the classes present:
   lower 26, upper 26, digit 10, ASCII symbol 33, other/non-ASCII 100 (coarse constant).
   Assumes every character is drawn uniformly at random — true only for generated passwords.
2. **Pattern penalties.** Each detected pattern replaces the covered characters' cost with a fixed cost:
   repeat run (≥3 same char) 2 bits; alphanumeric sequence (≥4) 4 bits; keyboard-row walk (≥4) 6 bits;
   "word + year/1–4 digits (+symbol)" suffix 7 bits. Costs are conservative round numbers, not measured values.
3. **Dictionary caps** (only if a local dataset is available): exact case-insensitive match ⇒ ≤ 20 bits
   (~1M guesses); lower-case / leet / trailing-affix-stripped match ⇒ ≤ 28 bits. Without a dataset the check is
   reported **NOT TESTED**, never silently passed.
4. **Rating bands** (effective bits): <28 very weak, <36 weak, <60 fair, <128 strong, ≥128 very strong.
   These are conventional heuristics. Every rating is labelled `[heuristic]`.

Known gaps: no Markov/PCFG modelling, no multi-word passphrase model, no leaked-password frequency data.
The shipped dataset (37 entries) is a demonstration fixture; point `common_passwords_file` at a real local list.
