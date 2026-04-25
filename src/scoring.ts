// Rule-based risk scorer. Pure function: (ScoringInput) => ScoringOutput.
// No dependencies, no side effects, no I/O.

export type Severity = "low" | "med" | "high";
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
// Per spec: < 10 low, 10-25 med, > 25 high.
function severityFor(points: number): Severity {
  if (points < 10) return "low";
  if (points <= 25) return "med";
  return "high";
}

function verdictFor(score: number): Verdict {
  if (score < 20) return "clean";
  if (score < 50) return "caution";
  if (score < 75) return "high_risk";
  return "do_not_interact";
}

type Rule = (ctx: ScoringInput) => Finding | null;

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
