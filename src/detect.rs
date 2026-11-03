//! Patch-based clone detection.
//!
//! A patch is described by two snippets: the code before the fix and the code
//! after it. Both are cut into overlapping k-token shingles. Shingles that
//! only the old code has are evidence of an unpatched file, shingles that only
//! the new code has are evidence of a patched one, and shingles both share
//! tell us whether the patched region exists in the file at all.
//!
//! The evidence is collected per candidate region, not over the whole file: a window about
//! as long as the snippet is slid over the target's shingle sequence and the best-covered
//! windows are scored one by one. This keeps a large flattened contract from polluting the
//! counts with unrelated shingles, and lets a file that holds two copies (one fixed, one
//! not) be judged copy by copy.

use crate::lexer::{canonical, decisive_literals, tokenize_semantic, Mode};
use std::collections::{HashMap, HashSet};

pub fn shingles(tokens: &[String], k: usize) -> HashSet<u64> {
    let mut set = HashSet::new();
    if k == 0 || tokens.len() < k {
        return set;
    }
    for w in tokens.windows(k) {
        set.insert(hash_window(w));
    }
    set
}

/// Hash of every k-token window, in order (the shingle sequence of a token stream).
pub fn shingle_hashes(tokens: &[String], k: usize) -> Vec<u64> {
    if k == 0 || tokens.len() < k {
        return Vec::new();
    }
    tokens.windows(k).map(hash_window).collect()
}

// FNV-1a over the tokens, with a separator so ["ab","c"] != ["a","bc"].
fn hash_window(w: &[String]) -> u64 {
    let mut h: u64 = 0xcbf29ce484222325;
    for t in w {
        for b in t.bytes() {
            h ^= b as u64;
            h = h.wrapping_mul(0x100000001b3);
        }
        h ^= 0xff;
        h = h.wrapping_mul(0x100000001b3);
    }
    h
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    Unpatched,
    Patched,
    Ambiguous,
    NoMatch,
}

impl Verdict {
    pub fn label(self) -> &'static str {
        match self {
            Verdict::Unpatched => "UNPATCHED",
            Verdict::Patched => "PATCHED",
            Verdict::Ambiguous => "AMBIGUOUS",
            Verdict::NoMatch => "NO_MATCH",
        }
    }
}

/// How the verdict was reached.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tier {
    /// The patch snippet appeared character for character (ignoring only
    /// layout and comments). No false positive is possible at this tier.
    Exact,
    /// Decided by token shingles; needs a manual check.
    Fuzzy,
}

impl Tier {
    pub fn label(self) -> &'static str {
        match self {
            Tier::Exact => "exact",
            Tier::Fuzzy => "fuzzy",
        }
    }
}

/// Snippets shorter than this (in canonical characters) are too generic for
/// an exact match to mean anything, so the exact tier skips them.
const MIN_EXACT_LEN: usize = 40;

/// Margin rule for UNPATCHED: at least this share of the old-only shingles must be present,
/// and that share must exceed the new-only share by at least `MARGIN_GAP`.
const MARGIN_MIN_EVIDENCE: f64 = 0.5;
const MARGIN_GAP: f64 = 0.5;

/// A candidate region is a window of this many times the longer snippet (counted in
/// shingles), so a few extra lines inside the copied code do not break it.
const WINDOW_FACTOR: usize = 2;
/// Upper bound on regions examined per file (copies of the patched code).
const MAX_REGIONS: usize = 6;
/// A window with fewer distinct patch shingles than this is not a candidate.
const MIN_REGION_HITS: usize = 3;

#[derive(Debug, Clone, Copy)]
pub struct Score {
    /// Share of the shared (context) shingles found in the target.
    pub context: f64,
    /// Share of the old-code-only shingles found in the target.
    pub old: f64,
    /// Share of the new-code-only shingles found in the target.
    pub new: f64,
    pub verdict: Verdict,
    pub tier: Tier,
}

pub struct Patch {
    old_text: String,
    new_text: String,
    context: HashSet<u64>,
    old_only: HashSet<u64>,
    new_only: HashSet<u64>,
    /// shingle -> 1 context, 2 old-only, 3 new-only
    kinds: HashMap<u64, u8>,
    /// Numeric literals the fix adds or removes; kept as written in normalized mode.
    keep: HashSet<String>,
    /// Length in shingles of the longer snippet.
    span: usize,
    mode: Mode,
    k: usize,
}

#[derive(Debug, Clone, Copy)]
struct Region {
    context: f64,
    old: f64,
    new: f64,
    verdict: Verdict,
}

impl Patch {
    /// Returns an error when the snippets are too short to yield any shingle
    /// that tells the old and new code apart.
    pub fn new(old_src: &str, new_src: &str, mode: Mode, k: usize) -> Result<Patch, String> {
        let literals = decisive_literals(old_src, new_src);
        let old_toks = tokenize_semantic(old_src, mode, Some(&literals));
        let new_toks = tokenize_semantic(new_src, mode, Some(&literals));
        let span = (old_toks.len().max(new_toks.len()) + 1).saturating_sub(k);
        let old = shingles(&old_toks, k);
        let new = shingles(&new_toks, k);
        if old.is_empty() && new.is_empty() {
            return Err(format!(
                "both snippets are shorter than {k} tokens; use longer snippets or a smaller --k"
            ));
        }
        let context: HashSet<u64> = old.intersection(&new).copied().collect();
        let old_only: HashSet<u64> = old.difference(&new).copied().collect();
        let new_only: HashSet<u64> = new.difference(&old).copied().collect();
        if old_only.is_empty() && new_only.is_empty() {
            return Err(
                "the old and new snippets are identical after normalization; \
                 nothing distinguishes a patched file from an unpatched one"
                    .to_string(),
            );
        }
        let keep = |s: String| if s.len() >= MIN_EXACT_LEN { s } else { String::new() };
        let mut kinds = HashMap::new();
        kinds.extend(context.iter().map(|h| (*h, 1u8)));
        kinds.extend(old_only.iter().map(|h| (*h, 2u8)));
        kinds.extend(new_only.iter().map(|h| (*h, 3u8)));
        Ok(Patch {
            old_text: keep(canonical(old_src)),
            new_text: keep(canonical(new_src)),
            context,
            old_only,
            new_only,
            kinds,
            keep: literals,
            span,
            mode,
            k,
        })
    }

    /// Independent occurrences of a snippet's canonical text: an occurrence inside a copy
    /// of the other snippet (one snippet containing the other) is not counted.
    fn independent(&self, text: &str, own: &str, other: &str) -> usize {
        if own.is_empty() {
            return 0;
        }
        let n = text.matches(own).count();
        if !other.is_empty() && other.len() > own.len() {
            let inside = other.matches(own).count();
            return n.saturating_sub(text.matches(other).count() * inside);
        }
        n
    }

    /// Two stages. Stage one looks for the snippets character for character.
    /// Only when that settles nothing does stage two compare token shingles.
    ///
    /// A vulnerable copy anywhere makes the file UNPATCHED, so an exact hit on the fixed code
    /// is not final: stage two still looks for a second, unfixed copy.
    pub fn score(&self, target_src: &str) -> Score {
        let text = canonical(target_src);
        let old_n = self.independent(&text, &self.old_text, &self.new_text);
        let new_n = self.independent(&text, &self.new_text, &self.old_text);
        if old_n > 0 {
            return Score {
                context: 1.0,
                old: 1.0,
                new: if new_n > 0 { 1.0 } else { 0.0 },
                verdict: Verdict::Unpatched,
                tier: Tier::Exact,
            };
        }
        if new_n > 0 {
            let fuzzy = self.score_fuzzy(target_src);
            if fuzzy.verdict == Verdict::Unpatched {
                return fuzzy;
            }
            return Score { context: 1.0, old: 0.0, new: 1.0, verdict: Verdict::Patched, tier: Tier::Exact };
        }
        self.score_fuzzy(target_src)
    }

    /// Verdict for one candidate region from its three coverage ratios.
    fn decide(&self, context: f64, old: f64, new: f64) -> Verdict {
        // When one side is empty (pure addition or pure deletion) its ratio is
        // meaningless, so it counts as "absent" for the other side's test.
        let old_present = !self.old_only.is_empty() && old >= 0.8;
        let old_absent = self.old_only.is_empty() || old < 0.2;
        let new_present = !self.new_only.is_empty() && new >= 0.8;
        let new_absent = self.new_only.is_empty() || new < 0.2;

        let region_found = if self.context.is_empty() {
            old_present || new_present
        } else {
            context >= 0.6
        };

        // A pure deletion leaves no new-only shingles to look for, so the
        // evidence of a fix is the region being there with the old code gone.
        let fixed_by_deletion = self.new_only.is_empty() && old_absent;

        // Margin rule: when the old-code evidence clearly outweighs the new-code evidence the
        // region is flagged even though the absolute 0.8 threshold is missed (old code with
        // some unrelated edits around it, e.g. old=0.58 against new=0.00). It is deliberately
        // one-sided. A wrong UNPATCHED is a lead that gets checked by hand; a wrong PATCHED
        // silently hides a vulnerable file, so PATCHED keeps the strict thresholds.
        let unpatched_by_margin = !self.old_only.is_empty()
            && old >= MARGIN_MIN_EVIDENCE
            && old - new >= MARGIN_GAP;

        if !region_found {
            Verdict::NoMatch
        } else if (new_present || fixed_by_deletion) && old_absent {
            Verdict::Patched
        } else if (new_absent && (old_present || self.old_only.is_empty())) || unpatched_by_margin {
            Verdict::Unpatched
        } else {
            Verdict::Ambiguous
        }
    }

    /// Coverage of the three shingle sets by the distinct patch shingles inside `[from, to)`.
    fn region_scores(&self, hashes: &[u64], kind: &[u8], from: usize, to: usize) -> Region {
        let mut seen: HashSet<u64> = HashSet::new();
        let mut count = [0usize; 4];
        for p in from..to {
            if kind[p] != 0 && seen.insert(hashes[p]) {
                count[kind[p] as usize] += 1;
            }
        }
        let share = |n: usize, set: &HashSet<u64>| if set.is_empty() { 0.0 } else { n as f64 / set.len() as f64 };
        let (context, old, new) = (
            share(count[1], &self.context),
            share(count[2], &self.old_only),
            share(count[3], &self.new_only),
        );
        Region { context, old, new, verdict: self.decide(context, old, new) }
    }

    /// Window of `w` shingle positions holding the most distinct patch shingles.
    fn best_window(kind: &[u8], hashes: &[u64], w: usize) -> Option<(usize, usize, usize)> {
        let m = kind.len();
        let mut counts: HashMap<u64, u32> = HashMap::new();
        let mut distinct = 0usize;
        let mut best: Option<(usize, usize, usize)> = None;
        for i in 0..m {
            if kind[i] != 0 {
                let c = counts.entry(hashes[i]).or_insert(0);
                *c += 1;
                if *c == 1 {
                    distinct += 1;
                }
            }
            if i >= w && kind[i - w] != 0 {
                let c = counts.get_mut(&hashes[i - w]).unwrap();
                *c -= 1;
                if *c == 0 {
                    distinct -= 1;
                }
            }
            let start = (i + 1).saturating_sub(w);
            if distinct >= MIN_REGION_HITS && best.map_or(true, |b| distinct > b.2) {
                best = Some((start, i + 1, distinct));
            }
        }
        best
    }

    fn score_fuzzy(&self, target_src: &str) -> Score {
        let tokens = tokenize_semantic(target_src, self.mode, Some(&self.keep));
        let hashes = shingle_hashes(&tokens, self.k);
        let mut kind: Vec<u8> = hashes.iter().map(|h| self.kinds.get(h).copied().unwrap_or(0)).collect();
        let w = (self.span * WINDOW_FACTOR).max(1);

        let mut found: Vec<Region> = Vec::new();
        let mut first: Option<Region> = None;
        for _ in 0..MAX_REGIONS {
            let Some((from, to, _)) = Self::best_window(&kind, &hashes, w) else { break };
            let r = self.region_scores(&hashes, &kind, from, to);
            first.get_or_insert(r);
            if r.verdict == Verdict::NoMatch {
                break; // windows come best first, so the rest are weaker still
            }
            found.push(r);
            // Mask the extent of this copy so the next round finds another one.
            let hits: Vec<usize> = (from..to).filter(|&p| kind[p] != 0).collect();
            for p in hits[0]..=hits[hits.len() - 1] {
                kind[p] = 0;
            }
        }

        // One vulnerable copy is enough for UNPATCHED; PATCHED needs every copy fixed.
        let pick = |v: Verdict, key: &dyn Fn(&Region) -> f64| {
            found
                .iter()
                .filter(|r| r.verdict == v)
                .max_by(|a, b| key(a).partial_cmp(&key(b)).unwrap_or(std::cmp::Ordering::Equal))
                .copied()
        };
        let chosen = pick(Verdict::Unpatched, &|r| r.old - r.new)
            .or_else(|| pick(Verdict::Ambiguous, &|r| r.context))
            .or_else(|| pick(Verdict::Patched, &|r| r.new))
            .or(first)
            .unwrap_or(Region { context: 0.0, old: 0.0, new: 0.0, verdict: Verdict::NoMatch });
        Score { context: chosen.context, old: chosen.old, new: chosen.new, verdict: chosen.verdict, tier: Tier::Fuzzy }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Illustrative snippets, not a real advisory: a missing zero-address check.
    const OLD: &str = "function setOwner(address next) external { require(msg.sender == owner); owner = next; }";
    const NEW: &str = "function setOwner(address next) external { require(msg.sender == owner); require(next != address(0)); owner = next; }";

    fn patch() -> Patch {
        Patch::new(OLD, NEW, Mode::Normalized, 4).unwrap()
    }

    #[test]
    fn old_code_is_flagged_even_with_renamed_identifiers() {
        let target = "function changeAdmin(address who) external { require(msg.sender == admin); admin = who; }";
        assert_eq!(patch().score(target).verdict, Verdict::Unpatched);
    }

    #[test]
    fn fixed_code_is_reported_as_patched() {
        let target = "function changeAdmin(address who) external { require(msg.sender == admin); require(who != address(0)); admin = who; }";
        assert_eq!(patch().score(target).verdict, Verdict::Patched);
    }

    #[test]
    fn unrelated_code_does_not_match() {
        let target = "function mint(uint256 amount) external { balance += amount; totalSupply += amount; }";
        assert_eq!(patch().score(target).verdict, Verdict::NoMatch);
    }

    #[test]
    fn pure_deletion_patches_are_detected_in_both_directions() {
        let old = "function f(bytes memory s) internal { if (s.length == 65) { return a(s); } else if (s.length == 64) { return b(s); } else { return c(); } }";
        let new = "function f(bytes memory s) internal { if (s.length == 65) { return a(s); } else { return c(); } }";
        let p = Patch::new(old, new, Mode::Normalized, 4).unwrap();
        assert_eq!(p.score(old).verdict, Verdict::Unpatched);
        assert_eq!(p.score(new).verdict, Verdict::Patched);
    }

    #[test]
    fn exact_tier_decides_first_when_only_layout_differs() {
        let target = "contract X {\n  // note\n  function setOwner(address next) external {\n    require(msg.sender == owner);\n    owner = next;\n  }\n}";
        let s = patch().score(target);
        assert_eq!((s.verdict, s.tier), (Verdict::Unpatched, Tier::Exact));
        let fixed = "function setOwner(address next) external { require(msg.sender == owner); require(next != address(0)); owner = next; }";
        let s = patch().score(fixed);
        assert_eq!((s.verdict, s.tier), (Verdict::Patched, Tier::Exact));
    }

    #[test]
    fn renamed_code_falls_through_to_the_fuzzy_tier() {
        let target = "function changeAdmin(address who) external { require(msg.sender == admin); admin = who; }";
        let s = patch().score(target);
        assert_eq!((s.verdict, s.tier), (Verdict::Unpatched, Tier::Fuzzy));
    }

    fn filler(n: usize) -> String {
        (0..n)
            .map(|i| format!("function f{i}(uint256 a) public returns (uint256) {{ uint256 b = a + {i}; if (b > a) {{ return b; }} return a; }}\n"))
            .collect()
    }

    #[test]
    fn old_code_inside_a_large_unrelated_contract_is_still_flagged() {
        let renamed = "function changeAdmin(address who) external { require(msg.sender == admin); admin = who; }";
        let target = format!("{}{}{}", filler(300), renamed, filler(300));
        assert_eq!(patch().score(&target).verdict, Verdict::Unpatched);
        let unrelated = filler(600);
        assert_eq!(patch().score(&unrelated).verdict, Verdict::NoMatch);
    }

    #[test]
    fn a_vulnerable_copy_next_to_a_fixed_copy_is_unpatched() {
        let fixed = "function setOwner(address next) external { require(msg.sender == owner); require(next != address(0)); owner = next; }";
        let renamed_old = "function changeAdmin(address who) external { require(msg.sender == admin); admin = who; }";
        // fixed copy found by the exact tier, vulnerable copy only by the fuzzy tier
        let target = format!("{fixed}\n{}\n{renamed_old}", filler(50));
        assert_eq!(patch().score(&target).verdict, Verdict::Unpatched);
        // both copies fixed
        let renamed_new = "function changeAdmin(address who) external { require(msg.sender == admin); require(who != address(0)); admin = who; }";
        let target = format!("{fixed}\n{}\n{renamed_new}", filler(50));
        assert_eq!(patch().score(&target).verdict, Verdict::Patched);
        // exact copies of both
        let target = format!("{OLD}\n{fixed}");
        assert_eq!(patch().score(&target).verdict, Verdict::Unpatched);
    }

    #[test]
    fn a_weaker_literal_in_the_fix_is_not_reported_as_patched() {
        let old = "function tail(bytes calldata d) internal view returns (address a) { if (trusted(msg.sender)) { assembly { a := shr(96, calldataload(sub(calldatasize(), 20))) } } else { return msg.sender; } }";
        let new = "function tail(bytes calldata d) internal view returns (address a) { if (trusted(msg.sender) && msg.data.length >= 20) { assembly { a := shr(96, calldataload(sub(calldatasize(), 20))) } } else { return msg.sender; } }";
        let p = Patch::new(old, new, Mode::Normalized, 4).unwrap();
        let fixed = "function pick(bytes calldata e) internal view returns (address w) { if (ok(msg.sender) && msg.data.length >= 20) { assembly { w := shr(96, calldataload(sub(calldatasize(), 20))) } } else { return msg.sender; } }";
        let weak = fixed.replace(">= 20", ">= 1");
        assert_eq!(p.score(fixed).verdict, Verdict::Patched);
        assert_ne!(p.score(&weak).verdict, Verdict::Patched);
    }

    #[test]
    fn verdict_labels_are_the_documented_four() {
        let all = [Verdict::Unpatched, Verdict::Patched, Verdict::Ambiguous, Verdict::NoMatch];
        let labels: Vec<_> = all.iter().map(|v| v.label()).collect();
        assert_eq!(labels, ["UNPATCHED", "PATCHED", "AMBIGUOUS", "NO_MATCH"]);
    }

    #[test]
    fn identical_snippets_are_rejected() {
        assert!(Patch::new(OLD, OLD, Mode::Normalized, 4).is_err());
    }

    #[test]
    fn too_short_snippets_are_rejected() {
        assert!(Patch::new("a b", "a c", Mode::Normalized, 4).is_err());
    }
}
