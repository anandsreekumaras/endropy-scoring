# Scoring methodology

endropy-scoring is a deterministic, additive rule engine. Given a
`ScoringInput`, every rule either returns a `Finding` (with points) or
`null`. The sum of points is clamped to the `[0, 100]` range and mapped
to a verdict.

## Rule table

| rule_id                    | Points | Severity | Triggers when                                                                        |
|----------------------------|-------:|----------|---------------------------------------------------------------------------------------|
| `deployer_funded_by_mixer` |   +35  | high     | Deployer's first funding came from a known mixer address (e.g. Tornado Cash router). |
| `deployer_fresh_wallet`    |   +15  | med      | Deployer's first-ever transaction was < 30 days before scan time.                    |
| `deployer_low_activity`    |   +10  | med      | Deployer has fewer than 10 transactions on record.                                   |
| `unverified_source`        |   +20  | med      | Contract is deployed but its Solidity source is not verified on Etherscan.           |
| `bytecode_high_similarity` |   +30  | high     | MinHash Jaccard ≥ 0.85 against any entry in the known-exploit corpus.                |
| `bytecode_med_similarity`  |   +15  | med      | MinHash Jaccard ≥ 0.70 and < 0.85 against any entry in the known-exploit corpus.     |

Note: `bytecode_high_similarity` and `bytecode_med_similarity` are
mutually exclusive — only the higher-tier match fires.

## Severity chips

Computed from the rule's points value (independent of the rule itself,
so hand-written rules and future auto-generated rules get chips
consistently):

| points range | severity |
|:------------:|----------|
| `< 10`       | low      |
| `10 ≤ p ≤ 25`| med      |
| `> 25`       | high     |

## Verdicts

| risk_score      | verdict            |
|-----------------|--------------------|
| `0 ≤ s < 20`    | `clean`            |
| `20 ≤ s < 50`   | `caution`          |
| `50 ≤ s < 75`   | `high_risk`        |
| `75 ≤ s ≤ 100`  | `do_not_interact`  |

## Bytecode similarity details

- Signature: MinHash with **128 permutations** over **4-byte shingles**
  of the raw bytecode (after stripping the `0x` prefix), stride 1
  (overlapping).
- Hash family: `h_i(x) = (a_i · x + b_i) mod (2³¹ − 1)`. The `(a_i, b_i)`
  pairs are derived from a fixed splitmix32 seed, so signatures are
  reproducible across processes and machines.
- `jaccardSimilarity(a, b)` = (count of positions where `a[i] === b[i]`)
  divided by 128.
- Empty / sub-4-byte bytecode yields `null` and is not comparable.

## Boundaries and known limits

- The scorer sees only the input you give it. It does not itself call
  any APIs, consult any block-explorer, or persist anything. All data
  plumbing (Alchemy / Etherscan / corpus DB) lives in the caller.
- Time-dependent rules (`deployer_fresh_wallet`) use the
  `scanned_at` timestamp from the input, not `Date.now()`. This lets
  callers replay historical scans reproducibly.
- Static seed lists (mixer addresses, known exchanges) live in the
  caller, not in this package. This package only reads the boolean
  `signals.mixer_funded` that the caller computed.
- Additive scoring has blind spots. A contract that is unverified AND
  has 30-day-fresh deployer AND is 100% bytecode-match to a known
  exploit maxes out at 20+15+30 = 65 — still below
  `do_not_interact`. The mixer rule is the only single-rule trigger
  that pushes into the top band.
- Jaccard on MinHash is a stochastic estimate. 128 permutations give
  roughly ±0.07 standard error near 0.5. For corpus matching we round
  to three decimals when rendering.
