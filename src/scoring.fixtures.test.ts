// Fixture tests for the scoring function. Run with:
//   npm test

import {
  scoreScan,
  rule_not_a_contract,
  type ScoringInput,
  type ScoringOutput,
} from "./scoring";
import assert from "node:assert/strict";

type Case = {
  name: string;
  input: ScoringInput;
  expect: ScoringOutput;
};

const cases: Case[] = [
  {
    name: "EOA — all defaults",
    input: {
      scanned_at: 1700000000,
      contract: { is_contract: false, is_verified: false },
      deployer: null,
      signals: { mixer_funded: false, fresh_wallet: false },
      activity_count: 0,
      corpus_match: null,
    },
    expect: { risk_score: 0, verdict: "clean", findings: [] },
  },
  {
    name: "verified contract, old deployer — clean",
    input: {
      scanned_at: 1700000000,
      contract: { is_contract: true, is_verified: true },
      deployer: { funded_by: "0xabc", first_seen_at: 1600000000 },
      signals: { mixer_funded: false, fresh_wallet: false },
      activity_count: 500,
      corpus_match: null,
    },
    expect: { risk_score: 0, verdict: "clean", findings: [] },
  },
  {
    name: "unverified contract — caution",
    input: {
      scanned_at: 1700000000,
      contract: { is_contract: true, is_verified: false },
      deployer: { funded_by: "0xabc", first_seen_at: 1600000000 },
      signals: { mixer_funded: false, fresh_wallet: false },
      activity_count: 500,
      corpus_match: null,
    },
    expect: {
      risk_score: 20,
      verdict: "caution",
      findings: [
        {
          rule_id: "unverified_source",
          points: 20,
          reason: "contract source code is not verified on Etherscan",
          severity: "med",
        },
      ],
    },
  },
  {
    name: "low activity fires only with a deployer",
    input: {
      scanned_at: 1700000000,
      contract: { is_contract: false, is_verified: false },
      deployer: null,
      signals: { mixer_funded: false, fresh_wallet: false },
      activity_count: 0,
      corpus_match: null,
    },
    expect: { risk_score: 0, verdict: "clean", findings: [] },
  },
  {
    name: "mixer-funded + fresh + low-activity + unverified — do_not_interact",
    input: {
      scanned_at: 1700000000,
      contract: { is_contract: true, is_verified: false },
      deployer: {
        funded_by: "0x722122df12d4e14e13ac3b6895a86e84145b6967",
        first_seen_at: 1700000000 - 86400 * 7, // 7 days ago
      },
      signals: { mixer_funded: true, fresh_wallet: true },
      activity_count: 3,
      corpus_match: null,
    },
    expect: {
      risk_score: 80,
      verdict: "do_not_interact",
      findings: [
        {
          rule_id: "deployer_funded_by_mixer",
          points: 35,
          reason: "deployer funded by a known mixer address (0x722122df12d4e14e13ac3b6895a86e84145b6967)",
          severity: "high",
        },
        {
          rule_id: "deployer_fresh_wallet",
          points: 15,
          reason: "deployer wallet is 7 days old (threshold: 30)",
          severity: "med",
        },
        {
          rule_id: "deployer_low_activity",
          points: 10,
          reason: "deployer has 3 txs on record (threshold: <10)",
          severity: "med",
        },
        {
          rule_id: "unverified_source",
          points: 20,
          reason: "contract source code is not verified on Etherscan",
          severity: "med",
        },
      ],
    },
  },
  {
    name: "bytecode high similarity match — caution if alone",
    input: {
      scanned_at: 1700000000,
      contract: { is_contract: true, is_verified: true },
      deployer: { funded_by: "0xabc", first_seen_at: 1600000000 },
      signals: { mixer_funded: false, fresh_wallet: false },
      activity_count: 100,
      corpus_match: { address: "0xdead", name: "DoomedDAO", jaccard: 1.0 },
    },
    expect: {
      risk_score: 30,
      verdict: "caution",
      findings: [
        {
          rule_id: "bytecode_high_similarity",
          points: 30,
          reason: 'bytecode closely matches known exploit "DoomedDAO" (jaccard 1.000)',
          severity: "high",
        },
      ],
    },
  },
  {
    name: "bytecode med similarity match",
    input: {
      scanned_at: 1700000000,
      contract: { is_contract: true, is_verified: true },
      deployer: { funded_by: "0xabc", first_seen_at: 1600000000 },
      signals: { mixer_funded: false, fresh_wallet: false },
      activity_count: 100,
      corpus_match: { address: "0xdead", name: null, jaccard: 0.75 },
    },
    expect: {
      risk_score: 15,
      verdict: "clean",
      findings: [
        {
          rule_id: "bytecode_med_similarity",
          points: 15,
          reason: 'bytecode partially resembles known exploit "0xdead" (jaccard 0.750)',
          severity: "med",
        },
      ],
    },
  },
  {
    name: "bytecode similarity below threshold — no finding",
    input: {
      scanned_at: 1700000000,
      contract: { is_contract: true, is_verified: true },
      deployer: { funded_by: "0xabc", first_seen_at: 1600000000 },
      signals: { mixer_funded: false, fresh_wallet: false },
      activity_count: 100,
      corpus_match: { address: "0xdead", name: "X", jaccard: 0.69 },
    },
    expect: { risk_score: 0, verdict: "clean", findings: [] },
  },
  {
    name: "score clamped to 100",
    input: {
      scanned_at: 1700000000,
      contract: { is_contract: true, is_verified: false },
      deployer: {
        funded_by: "0x722122df12d4e14e13ac3b6895a86e84145b6967",
        first_seen_at: 1700000000 - 86400 * 7,
      },
      signals: { mixer_funded: true, fresh_wallet: true },
      activity_count: 3,
      corpus_match: { address: "0xdead", name: "X", jaccard: 1.0 },
    },
    expect: {
      risk_score: 100, // 35+15+10+20+30 = 110, clamped to 100
      verdict: "do_not_interact",
      findings: [
        {
          rule_id: "deployer_funded_by_mixer",
          points: 35,
          reason: "deployer funded by a known mixer address (0x722122df12d4e14e13ac3b6895a86e84145b6967)",
          severity: "high",
        },
        {
          rule_id: "deployer_fresh_wallet",
          points: 15,
          reason: "deployer wallet is 7 days old (threshold: 30)",
          severity: "med",
        },
        {
          rule_id: "deployer_low_activity",
          points: 10,
          reason: "deployer has 3 txs on record (threshold: <10)",
          severity: "med",
        },
        {
          rule_id: "unverified_source",
          points: 20,
          reason: "contract source code is not verified on Etherscan",
          severity: "med",
        },
        {
          rule_id: "bytecode_high_similarity",
          points: 30,
          reason: 'bytecode closely matches known exploit "X" (jaccard 1.000)',
          severity: "high",
        },
      ],
    },
  },
  {
    name: "verdict boundary: 19 → clean, 20 → caution",
    input: {
      scanned_at: 1700000000,
      contract: { is_contract: true, is_verified: false },
      deployer: null,
      signals: { mixer_funded: false, fresh_wallet: false },
      activity_count: 0,
      corpus_match: null,
    },
    expect: {
      risk_score: 20,
      verdict: "caution",
      findings: [
        {
          rule_id: "unverified_source",
          points: 20,
          reason: "contract source code is not verified on Etherscan",
          severity: "med",
        },
      ],
    },
  },
  {
    name: "ofac_sanctioned alone — critical, do_not_interact at score 100",
    input: {
      scanned_at: 1700000000,
      contract: { is_contract: true, is_verified: true },
      deployer: { funded_by: "0xabc", first_seen_at: 1600000000 },
      signals: { mixer_funded: false, fresh_wallet: false, ofac_sanctioned: true },
      activity_count: 500,
      corpus_match: null,
    },
    expect: {
      risk_score: 100,
      verdict: "do_not_interact",
      findings: [
        {
          rule_id: "ofac_sanctioned",
          points: 100,
          reason:
            "address is on the OFAC SDN sanctions list — transacting may violate U.S. sanctions law",
          severity: "critical",
        },
      ],
    },
  },
  {
    name: "ofac_sanctioned stacks with other findings — still capped at 100",
    input: {
      scanned_at: 1700000000,
      contract: { is_contract: true, is_verified: false },
      deployer: {
        funded_by: "0x722122df12d4e14e13ac3b6895a86e84145b6967",
        first_seen_at: 1700000000 - 86400 * 7,
      },
      signals: { mixer_funded: true, fresh_wallet: true, ofac_sanctioned: true },
      activity_count: 3,
      corpus_match: null,
    },
    expect: {
      risk_score: 100, // 100+35+15+10+20 = 180, clamped to 100
      verdict: "do_not_interact",
      findings: [
        {
          rule_id: "ofac_sanctioned",
          points: 100,
          reason:
            "address is on the OFAC SDN sanctions list — transacting may violate U.S. sanctions law",
          severity: "critical",
        },
        {
          rule_id: "deployer_funded_by_mixer",
          points: 35,
          reason: "deployer funded by a known mixer address (0x722122df12d4e14e13ac3b6895a86e84145b6967)",
          severity: "high",
        },
        {
          rule_id: "deployer_fresh_wallet",
          points: 15,
          reason: "deployer wallet is 7 days old (threshold: 30)",
          severity: "med",
        },
        {
          rule_id: "deployer_low_activity",
          points: 10,
          reason: "deployer has 3 txs on record (threshold: <10)",
          severity: "med",
        },
        {
          rule_id: "unverified_source",
          points: 20,
          reason: "contract source code is not verified on Etherscan",
          severity: "med",
        },
      ],
    },
  },
  {
    name: "ofac_sanctioned omitted — does not fire",
    input: {
      scanned_at: 1700000000,
      contract: { is_contract: true, is_verified: true },
      deployer: { funded_by: "0xabc", first_seen_at: 1600000000 },
      signals: { mixer_funded: false, fresh_wallet: false }, // ofac_sanctioned absent
      activity_count: 500,
      corpus_match: null,
    },
    expect: { risk_score: 0, verdict: "clean", findings: [] },
  },
];

let pass = 0;
let fail = 0;
for (const c of cases) {
  try {
    const out = scoreScan(c.input);
    assert.deepStrictEqual(out, c.expect);
    console.log(`pass  ${c.name}`);
    pass++;
  } catch (e) {
    console.error(`FAIL  ${c.name}`);
    console.error(e);
    fail++;
  }
}

// rule_not_a_contract is exported standalone (not in default RULES) so EOA
// tagging is opt-in. Test it directly here.
function check(name: string, fn: () => void): void {
  try {
    fn();
    console.log(`pass  ${name}`);
    pass++;
  } catch (e) {
    console.error(`FAIL  ${name}`);
    console.error(e);
    fail++;
  }
}

const eoaInput: ScoringInput = {
  scanned_at: 1700000000,
  contract: { is_contract: false, is_verified: false },
  deployer: null,
  signals: { mixer_funded: false, fresh_wallet: false },
  activity_count: 0,
  corpus_match: null,
};

check("rule_not_a_contract: fires for EOA with info severity", () => {
  const out = rule_not_a_contract(eoaInput);
  assert.deepStrictEqual(out, {
    rule_id: "not_a_contract",
    points: 0,
    reason:
      "address is an EOA (externally owned account); contract-analysis rules don't apply. sanctions screening is the only check available for wallets in v0.1",
    severity: "info",
  });
});

check("rule_not_a_contract: returns null for a contract", () => {
  const out = rule_not_a_contract({
    ...eoaInput,
    contract: { is_contract: true, is_verified: true },
  });
  assert.strictEqual(out, null);
});

console.log(`\n${pass}/${pass + fail} fixtures passed`);
if (fail > 0) process.exit(1);
