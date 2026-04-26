// Rule-based risk scorer. Pure function: (ScoringInput) => ScoringOutput.
// No dependencies, no side effects, no I/O.

export type Severity = "info" | "low" | "med" | "high" | "critical";
export type Verdict = "clean" | "caution" | "high_risk" | "do_not_interact";

export type Finding = {
  rule_id: string;
  points: number;
  reason: string;
  severity: Severity;
};

export type CorpusMatch = {
  address: string;
  name: string | null;
  jaccard: number;
};

export type ScoringInput = {
  scanned_at: number;
  contract: {
    is_contract: boolean;
    is_verified: boolean;
  };
  deployer: {
    funded_by: string | null;
    first_seen_at: number | null;
  } | null;
  signals: {
    mixer_funded: boolean;
    fresh_wallet: boolean;
    ofac_sanctioned?: boolean;
  };
  activity_count: number;
  corpus_match: CorpusMatch | null;
};

export type ScoringOutput = {
  risk_score: number;
  verdict: Verdict;
  findings: Finding[];
};

// Severity bands by points value.
//   p === 0          → info     (descriptive, non-scoring)
//   0 < p < 10       → low
//   10 ≤ p ≤ 25      → med
//   25 < p < 100     → high
//   p ≥ 100          → critical (single-rule trip into do_not_interact)
function severityFor(points: number): Severity {
  if (points <= 0) return "info";
  if (points < 10) return "low";
  if (points <= 25) return "med";
  if (points < 100) return "high";
  return "critical";
}

function verdictFor(score: number): Verdict {
  if (score < 20) return "clean";
  if (score < 50) return "caution";
  if (score < 75) return "high_risk";
  return "do_not_interact";
}

export type Rule = (ctx: ScoringInput) => Finding | null;

// ofac_sanctioned: address is on the U.S. Treasury OFAC SDN list.
// The boolean signal is filled at the runtime layer (in endropy.xyz, a
// Cloudflare Worker that consults a daily-refreshed list cached in KV);
// this package only owns the rule's id, weight, severity, and reason.
export const rule_ofac_sanctioned: Rule = (ctx) => {
  if (!ctx.signals.ofac_sanctioned) return null;
  const points = 100;
  return {
    rule_id: "ofac_sanctioned",
    points,
    reason:
      "address is on the OFAC SDN sanctions list — transacting may violate U.S. sanctions law",
    severity: severityFor(points),
  };
};

// not_a_contract: address is an EOA. Pure function on input. Exported
// standalone (not in default RULES) so callers can opt in to EOA tagging
// without changing the score-only output of scoreScan().
export const rule_not_a_contract: Rule = (ctx) => {
  if (ctx.contract.is_contract) return null;
  const points = 0;
  return {
    rule_id: "not_a_contract",
    points,
    reason:
      "address is an EOA (externally owned account); contract-analysis rules don't apply. sanctions screening is the only check available for wallets in v0.1",
    severity: severityFor(points),
  };
};

const rule_deployer_funded_by_mixer: Rule = (ctx) => {
  if (!ctx.signals.mixer_funded) return null;
  const points = 35;
  const who = ctx.deployer?.funded_by ?? "known mixer";
  return {
    rule_id: "deployer_funded_by_mixer",
    points,
    reason: `deployer funded by a known mixer address (${who})`,
    severity: severityFor(points),
  };
};

const rule_deployer_fresh_wallet: Rule = (ctx) => {
  if (!ctx.signals.fresh_wallet) return null;
  const points = 15;
  const firstSeen = ctx.deployer?.first_seen_at ?? null;
  const ageDays = firstSeen
    ? Math.floor((ctx.scanned_at - firstSeen) / 86400)
    : null;
  return {
    rule_id: "deployer_fresh_wallet",
    points,
    reason: `deployer wallet is ${ageDays ?? "<30"} days old (threshold: 30)`,
    severity: severityFor(points),
  };
};

const rule_deployer_low_activity: Rule = (ctx) => {
  if (!ctx.deployer) return null;
  if (ctx.activity_count >= 10) return null;
  const points = 10;
  return {
    rule_id: "deployer_low_activity",
    points,
    reason: `deployer has ${ctx.activity_count} txs on record (threshold: <10)`,
    severity: severityFor(points),
  };
};

const rule_unverified_source: Rule = (ctx) => {
  if (!ctx.contract.is_contract) return null;
  if (ctx.contract.is_verified) return null;
  const points = 20;
  return {
    rule_id: "unverified_source",
    points,
    reason: "contract source code is not verified on Etherscan",
    severity: severityFor(points),
  };
};

const rule_bytecode_similarity: Rule = (ctx) => {
  const m = ctx.corpus_match;
  if (!m) return null;
  const label = m.name ?? m.address;
  const j = m.jaccard.toFixed(3);
  if (m.jaccard >= 0.85) {
    const points = 30;
    return {
      rule_id: "bytecode_high_similarity",
      points,
      reason: `bytecode closely matches known exploit "${label}" (jaccard ${j})`,
      severity: severityFor(points),
    };
  }
  if (m.jaccard >= 0.7) {
    const points = 15;
    return {
      rule_id: "bytecode_med_similarity",
      points,
      reason: `bytecode partially resembles known exploit "${label}" (jaccard ${j})`,
      severity: severityFor(points),
    };
  }
  return null;
};

export const RULES: Rule[] = [
  rule_ofac_sanctioned,
  rule_deployer_funded_by_mixer,
  rule_deployer_fresh_wallet,
  rule_deployer_low_activity,
  rule_unverified_source,
  rule_bytecode_similarity,
];

export function scoreScan(ctx: ScoringInput): ScoringOutput {
  const findings: Finding[] = [];
  for (const r of RULES) {
    const f = r(ctx);
    if (f) findings.push(f);
  }
  const sum = findings.reduce((acc, f) => acc + f.points, 0);
  const risk_score = Math.min(100, sum);
  return { risk_score, verdict: verdictFor(risk_score), findings };
}
