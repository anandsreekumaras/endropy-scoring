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

- `src/` — the rule engine, score aggregation, and verdict logic.
- `src/scoring.fixtures.test.ts` — fixture tests demonstrating that each rule
  fires correctly on known inputs.
- `package.json` — minimal dependencies (TypeScript only).

## What's not included

The exploit corpus used for bytecode-similarity matching is maintained
separately and is not part of this repo. The matching algorithm (MinHash on
opcode sequences) is open; the dataset is curated from public sources but
not redistributed here for security reasons.

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
