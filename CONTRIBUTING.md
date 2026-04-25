# Contributing to endropy-scoring

## Dev setup

```sh
npm install
npm test            # run the fixture tests
npm run typecheck   # tsc --noEmit
```

There is no build step — consumers import directly from `src/`. The
TypeScript config uses `"moduleResolution": "Bundler"`, which both
Cloudflare Workers (esbuild) and modern Node happily resolve.

## Adding a rule

1. Write the rule function in `src/scoring.ts`. Signature:
   ```ts
   const rule_my_name: Rule = (ctx) => {
     if (!/* your predicate */) return null;
     const points = /* weight */;
     return {
       rule_id: "my_name",
       points,
       reason: "human-readable, past tense, references observable fact",
       severity: severityFor(points),
     };
   };
   ```
2. Append it to the `RULES` array. Order does not affect the score,
   but it does affect `findings[]` ordering; keep related rules
   grouped.
3. Add a row to [SCORING.md](./SCORING.md) in the same revision.
4. Add a test case in `src/scoring.fixtures.test.ts`: one case where the
   rule fires, one case where it must not.

## Review bar for new rules

A rule ships only if it clears all of these:

- **Observable.** The input condition is a field on `ScoringInput`.
  If you need a new field, argue for it — callers have to fill it.
- **Non-opinionated.** "The contract looks scammy" is not a rule.
  "No Etherscan verification" is a rule.
- **Low false-positive rate.** The rule must not fire on Uniswap V2
  Router, USDC, WETH, or any of the top 50 contracts by usage. Run
  the rule against real bytecode for those contracts before opening
  a PR.
- **Weight justified.** Light-touch rules (<10 points) should be
  things that are common even on legitimate contracts. Heavy rules
  (>25 points) must correspond to red flags that are rare outside of
  real exploits.

## What we won't merge

- Rules that require calling external APIs from inside the scorer.
  Keep this package pure.
- Rules that encode opinions about specific protocols, teams, or
  audits.
- ML-based scoring. We want every point to be explainable in one
  sentence.
- Rules that can only be evaluated by inspecting Solidity source.
  (Source-based rules will live in a sibling package in a future
  phase, not here.)

## License

By contributing, you agree that your contributions are licensed under
the [MIT License](./LICENSE).
