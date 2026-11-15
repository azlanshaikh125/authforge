# Risk intelligence & prioritization model (Milestone 2)

`lib/risk.sh` and `modules/risk.sh` implement a deterministic, CVSS-inspired composite scoring and correlation model over session findings.

## 1. Composite risk score (`0.1` .. `10.0`)

Each unique finding is scored from five factors plus any active correlation boost:

$$\text{Score} = \min\!\left(10.0,\; B_{\text{sev}} \times \left(0.45 + 0.30\,W_{\text{lik}} + 0.25\,W_{\text{imp}}\right) \times W_{\text{conf}} \times W_{\text{basis}} + C_{\text{boost}}\right)$$

- **Base severity weight ($B_{\text{sev}}$)**: `CRITICAL = 9.8`, `HIGH = 8.0`, `MEDIUM = 5.5`, `LOW = 3.0`, `INFO = 1.0`.
- **Likelihood weight ($W_{\text{lik}}$)**: `VERY_HIGH = 1.00` (exact common password, broken algorithm, cleartext/empty marker), `HIGH = 0.85` (unsalted digest, legacy KDF, reused credential/hash, leet variant), `MEDIUM = 0.70` (suboptimal KDF work factor, policy threshold gap), `LOW = 0.55` (heuristic observation, formatting/encoding hygiene).
- **Impact weight ($W_{\text{imp}}$)**: `CRITICAL = 1.00` (multi-account or policy-wide critical exposure), `HIGH = 0.88` (single-credential or dataset compromise), `MEDIUM = 0.72` (moderate policy/configuration weakness), `LOW = 0.55` (informational/wordlist hygiene).
- **Confidence multiplier ($W_{\text{conf}}$)**: `HIGH = 1.00`, `MEDIUM = 0.88`, `LOW = 0.75`.
- **Basis multiplier ($W_{\text{basis}}$)**: `verified = 1.00`, `heuristic = 0.90`.

## 2. Priority tiers & ordering

Active findings are sorted by Priority Group, Composite Score (descending), Severity Rank, Confidence Rank, Basis, and Occurrence Count:
- `P1-IMMEDIATE`: $\text{Score} \ge 8.5$ or `CRITICAL` severity.
- `P2-HIGH`: $\text{Score} \ge 6.5$ or (`HIGH` severity with $\text{Score} \ge 5.5$).
- `P3-MEDIUM`: $\text{Score} \ge 3.5$ or `MEDIUM` severity.
- `P4-LOW`: $\text{Score} \ge 1.8$ or `LOW` severity.
- `P5-INFO`: $\text{Score} < 1.8$ (`INFO` severity).
- `SUPPRESSED`: Findings marked `false_positive` or `risk_accepted` via `authforge risk suppress` (retained in exports with status and reason, excluded from active posture penalties).

## 3. Deduplication & correlation chains

1. **Canonical deduplication**: Findings with identical `module | severity | confidence | basis | title | evidence` are collapsed into one prioritized entry with `occurrences = N`.
2. **Correlation rules**:
   - `CORR-01` (`CRITICAL`, `+0.6` boost): Weak/common passwords co-occurring with weak/broken/legacy hashes.
   - `CORR-02` (`HIGH`, `+0.4` boost): Permissive policy review findings co-occurring with dataset weaknesses.
   - `CORR-03` (`HIGH`, `+0.4` boost): Credential/hash reuse combined with unsalted storage.
   - `CORR-04` (`MEDIUM`, `+0.2` boost): Wordlist policy exposure overlapping with password/policy weaknesses.
