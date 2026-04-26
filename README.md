# endropy-scoring

The scoring engine that powers [endropy.xyz](https://endropy.xyz) — a free
Ethereum smart contract risk scanner.

This repository contains the exact rules, weights, and tests used to compute
risk verdicts on contracts scanned via endropy. Every score visible on the
live site comes from this code.

## Why open source?

Endropy's pitch is transparency, not a black box. If we tell you a contract
is high-risk, you should be able to verify exactly why — and disagree if our
methodology is wrong.

## What's included

- `src/scoring.ts` — the rule engine, score aggregation, and verdict logic.
  Includes `ofac_sanctioned`, `deployer_funded_by_mixer`,
  `deployer_fresh_wallet`, `deployer_low_activity`, `unverified_source`,
  `bytecode_high_similarity`, `bytecode_med_similarity`, plus the
  standalone informational rule `not_a_contract`.
- `src/bytecode.ts` — MinHash signatures and Jaccard similarity for
  bytecode comparison.
- `src/scoring.fixtures.test.ts` — fixture tests demonstrating that each
  rule fires correctly on known inputs.
- `package.json` — TypeScript only; no runtime dependencies.

## What's not included

The exploit corpus used for bytecode-similarity matching is maintained
separately and is not part of this repo. The matching algorithm (MinHash on
opcode sequences) is open; the dataset is curated from public sources but
not redistributed here for security reasons.

## Runtime-evaluated rules

Some rules require runtime context (live API calls, KV cache, etc.) and
can't be fully evaluated within this package alone. Their definitions
live here so the schema and scoring weights are public and auditable, but
their input booleans are computed in endropy.xyz's Cloudflare Worker and
passed in via `ScoringInput.signals`:

- `ofac_sanctioned` — checks the address against the OFAC SDN sanctions
  list, refreshed daily by a Cloudflare Worker cron job. Source:
  [community mirror](https://github.com/0xB10C/ofac-sanctioned-digital-currency-addresses)
  of the U.S. Department of the Treasury list.
- `deployer_funded_by_mixer` — depends on a curated list of mixer
  addresses (Tornado Cash routers, etc.) maintained outside this package.

## Running the tests

```bash
npm install
npm test
```

## How endropy uses this

endropy.xyz fetches a contract's bytecode and on-chain history, runs each
rule in `src/scoring.ts`, then aggregates the weighted findings into a final
verdict. The same code runs on the live site as runs in these tests.

## Reference

- [SCORING.md](./SCORING.md) — full rule table, weights, verdict thresholds.
- [CONTRIBUTING.md](./CONTRIBUTING.md) — adding rules, review bar.

## Disagreeing with our methodology

If you think a rule is wrong, weighted incorrectly, or missing entirely —
open an issue. Concrete cases (with example contracts) are far more useful
than abstract arguments.

## Disclaimer

endropy provides data, not advice. A "clean" verdict means our rules didn't
fire — not that the contract is safe. Always verify with multiple sources
before trusting any contract with funds.

## License

MIT — see [LICENSE](./LICENSE).

