//! Minimal Solidity lexer. It does not parse; it only turns source text into
//! a flat token stream with comments and whitespace removed, which is all the
//! clone detector needs.

use std::collections::{HashMap, HashSet};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mode {
    /// Keep identifiers and literals as written (Type-1 clones).
    Exact,
    /// Replace identifiers with `ID` and literals with `LIT`, keeping
    /// keywords, built-in members and operators (Type-2 clones).
    Normalized,
}

const OPS: [&str; 20] = [
    "==", "!=", "<=", ">=", "&&", "||", "++", "--", "+=", "-=", "*=", "/=", "%=", "**", "<<", ">>",
    "=>", "->", "&=", "|=",
];

const KEYWORDS: &[&str] = &[
    "pragma", "contract", "library", "interface", "function", "modifier", "event", "error",
    "struct", "enum", "mapping", "public", "private", "internal", "external", "view", "pure",
    "payable", "returns", "return", "if", "else", "for", "while", "do", "break", "continue",
    "require", "revert", "assert", "emit", "new", "delete", "memory", "storage", "calldata",
    "constructor", "fallback", "receive", "override", "virtual", "abstract", "is", "using",
    "import", "from", "as", "try", "catch", "unchecked", "immutable", "constant", "indexed",
    "anonymous", "this", "super", "msg", "block", "tx", "abi", "address", "bool", "string",
    "bytes", "uint", "int", "true", "false", "assembly", "let", "switch", "case", "default",
    "selfdestruct", "type", "sender", "value", "data", "timestamp", "number", "origin",
    "balance", "length", "push", "pop", "call", "delegatecall", "staticcall", "transfer", "send",
    "encode", "encodePacked", "keccak256", "ecrecover", "sha256", "wei", "ether", "gwei",
];

fn is_keyword(word: &str) -> bool {
    if KEYWORDS.contains(&word) {
        return true;
    }
    // Sized types: uint8..uint256, int8..int256, bytes1..bytes32.
    for prefix in ["uint", "int", "bytes"] {
        if let Some(rest) = word.strip_prefix(prefix) {
            if !rest.is_empty() && rest.bytes().all(|b| b.is_ascii_digit()) {
                return true;
            }
        }
    }
    false
}

fn is_ident_start(b: u8) -> bool {
    b.is_ascii_alphabetic() || b == b'_' || b == b'$'
}

fn is_ident_part(b: u8) -> bool {
    is_ident_start(b) || b.is_ascii_digit()
}

pub fn tokenize(src: &str, mode: Mode) -> Vec<String> {
    tokenize_keeping(src, mode, None)
}

/// Numeric literals whose number of occurrences differs between the old and the new snippet.
/// They are part of the fix itself (`>= 20` added to a guard, a `64` branch removed), so the
/// normalized stream keeps them as written instead of collapsing them to `LIT`.
pub fn decisive_literals(old_src: &str, new_src: &str) -> HashSet<String> {
    let count = |src: &str| {
        let mut m: HashMap<String, usize> = HashMap::new();
        for t in tokenize(src, Mode::Exact) {
            if t.as_bytes()[0].is_ascii_digit() {
                *m.entry(t).or_insert(0) += 1;
            }
        }
        m
    };
    let (o, n) = (count(old_src), count(new_src));
    let mut keys: HashSet<&String> = o.keys().collect();
    keys.extend(n.keys());
    keys.into_iter()
        .filter(|k| o.get(*k).copied().unwrap_or(0) != n.get(*k).copied().unwrap_or(0))
        .cloned()
        .collect()
}

pub fn tokenize_keeping(src: &str, mode: Mode, keep: Option<&HashSet<String>>) -> Vec<String> {
    let b = src.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;

    while i < b.len() {
        let c = b[i];

        if c.is_ascii_whitespace() {
            i += 1;
        } else if c == b'/' && b.get(i + 1) == Some(&b'/') {
            while i < b.len() && b[i] != b'\n' {
                i += 1;
            }
        } else if c == b'/' && b.get(i + 1) == Some(&b'*') {
            i += 2;
            while i + 1 < b.len() && !(b[i] == b'*' && b[i + 1] == b'/') {
                i += 1;
            }
            i = (i + 2).min(b.len());
        } else if c == b'"' || c == b'\'' {
            let quote = c;
            let start = i;
            i += 1;
            while i < b.len() && b[i] != quote {
                if b[i] == b'\\' {
                    i += 1;
                }
                i += 1;
            }
            i = (i + 1).min(b.len());
            out.push(match mode {
                Mode::Exact => src[start..i].to_string(),
                Mode::Normalized => "LIT".to_string(),
            });
        } else if c.is_ascii_digit() {
            let start = i;
            while i < b.len() && (b[i].is_ascii_alphanumeric() || b[i] == b'_' || b[i] == b'.') {
                i += 1;
            }
            let text = &src[start..i];
            out.push(match mode {
                Mode::Normalized if !keep.map_or(false, |k| k.contains(text)) => "LIT".to_string(),
                _ => text.to_string(),
            });
        } else if is_ident_start(c) {
            let start = i;
            while i < b.len() && is_ident_part(b[i]) {
                i += 1;
            }
            let word = &src[start..i];
            out.push(match mode {
                Mode::Normalized if !is_keyword(word) => "ID".to_string(),
                _ => word.to_string(),
            });
        } else {
            let two = src.get(i..i + 2).unwrap_or("");
            if OPS.contains(&two) {
                out.push(two.to_string());
                i += 2;
            } else if c.is_ascii() {
                out.push((c as char).to_string());
                i += 1;
            } else {
                // Skip non-ASCII bytes outside strings and comments.
                i += 1;
                while i < b.len() && (b[i] & 0xC0) == 0x80 {
                    i += 1;
                }
            }
        }
    }
    out
}

// ---------------------------------------------------------------------------------------
// Guard unification (fuzzy stage only).
//
// `require(c, "m")`, `if (!c) revert E();` and `if (!c) { revert E(); }` all mean "revert
// unless c holds". They are rewritten to one shape, `require ( c ) ;`, so a fix written as
// a custom-error guard still matches a snippet written with `require`, and the other way
// round. The message / error is dropped on purpose: it is a literal anyway (LIT / ID in
// normalized mode) and never decides whether the guard exists.
//
// This works on the token stream, not on a parse tree. It only rewrites the three exact
// shapes above; anything it does not understand is left untouched, so the worst case is the
// old behaviour. The exact tier (`canonical`) never sees this pass.
// ---------------------------------------------------------------------------------------

const COMPARE: [&str; 6] = ["==", "!=", "<", "<=", ">", ">="];
const BINARY: [&str; 20] = [
    "&&", "||", "==", "!=", "<", "<=", ">", ">=", "+", "-", "*", "/", "%", "?", "&", "|", "^", "<<",
    ">>", "**",
];

fn is_open(t: &str) -> bool {
    matches!(t, "(" | "[" | "{")
}

fn is_close(t: &str) -> bool {
    matches!(t, ")" | "]" | "}")
}

/// Index of the bracket that closes the one at `open`.
fn matching(toks: &[String], open: usize) -> Option<usize> {
    let mut depth = 0usize;
    for (i, t) in toks.iter().enumerate().skip(open) {
        if is_open(t) {
            depth += 1;
        } else if is_close(t) {
            depth = depth.checked_sub(1)?;
            if depth == 0 {
                return Some(i);
            }
        }
    }
    None
}

/// Positions of top-level (bracket depth 0) tokens that satisfy `pred`.
fn top_level(toks: &[String], pred: impl Fn(&str) -> bool) -> Vec<usize> {
    let mut depth = 0usize;
    let mut out = Vec::new();
    for (i, t) in toks.iter().enumerate() {
        if is_open(t) {
            depth += 1;
        } else if is_close(t) {
            depth = depth.saturating_sub(1);
        } else if depth == 0 && pred(t) {
            out.push(i);
        }
    }
    out
}

fn split_at_top(toks: &[String], sep: &str) -> Vec<Vec<String>> {
    let mut parts = Vec::new();
    let mut from = 0;
    for i in top_level(toks, |t| t == sep) {
        parts.push(toks[from..i].to_vec());
        from = i + 1;
    }
    parts.push(toks[from..].to_vec());
    parts
}

fn strip_parens(toks: &[String]) -> &[String] {
    let mut s = toks;
    while s.len() >= 2 && s[0] == "(" && matching(s, 0) == Some(s.len() - 1) {
        s = &s[1..s.len() - 1];
    }
    s
}

/// One operand: a parenthesised group, or a chain with no top-level binary operator.
fn is_operand(toks: &[String]) -> bool {
    !toks.is_empty()
        && (toks[0] == "(" && matching(toks, 0) == Some(toks.len() - 1)
            || top_level(toks, |t| BINARY.contains(&t)).is_empty())
}

/// Logical negation of a condition, pushed through `!`, `&&`, `||` and one comparison.
fn negate(cond: &[String]) -> Vec<String> {
    let c = strip_parens(cond);
    if c.is_empty() {
        return Vec::new();
    }
    if c[0] == "!" && is_operand(&c[1..]) {
        return strip_parens(&c[1..]).to_vec();
    }
    if top_level(c, |t| t == "?").is_empty() {
        let ors = split_at_top(c, "||");
        if ors.len() > 1 {
            // !(a || b) == !a && !b ; a part that turns into an `||` needs parentheses
            let mut out = Vec::new();
            for (i, p) in ors.iter().enumerate() {
                if i > 0 {
                    out.push("&&".to_string());
                }
                let n = negate(p);
                if top_level(&n, |t| t == "||").is_empty() {
                    out.extend(n);
                } else {
                    out.push("(".to_string());
                    out.extend(n);
                    out.push(")".to_string());
                }
            }
            return out;
        }
        let ands = split_at_top(c, "&&");
        if ands.len() > 1 {
            let mut out = Vec::new();
            for (i, p) in ands.iter().enumerate() {
                if i > 0 {
                    out.push("||".to_string());
                }
                out.extend(negate(p));
            }
            return out;
        }
        let cmp = top_level(c, |t| COMPARE.contains(&t));
        if cmp.len() == 1 {
            let flipped = match c[cmp[0]].as_str() {
                "==" => "!=",
                "!=" => "==",
                "<" => ">=",
                "<=" => ">",
                ">" => "<=",
                _ => "<",
            };
            let mut out = c.to_vec();
            out[cmp[0]] = flipped.to_string();
            return out;
        }
    }
    let mut out = vec!["!".to_string()];
    if is_operand(c) && c[0] != "(" {
        out.extend(c.iter().cloned());
    } else {
        out.push("(".to_string());
        out.extend(c.iter().cloned());
        out.push(")".to_string());
    }
    out
}

/// `revert`, an optional (qualified) error name and an optional argument list, up to and
/// including the `;`. Returns the index just past the statement.
fn revert_stmt_end(toks: &[String], at: usize) -> Option<usize> {
    if toks.get(at).map(String::as_str) != Some("revert") {
        return None;
    }
    let mut i = at + 1;
    while i < toks.len() && toks[i] != "(" && toks[i] != ";" {
        i += 1;
    }
    if toks.get(i).map(String::as_str) == Some("(") {
        i = matching(toks, i)? + 1;
    }
    (toks.get(i).map(String::as_str) == Some(";")).then_some(i + 1)
}

fn emit_require(out: &mut Vec<String>, cond: &[String]) {
    out.push("require".to_string());
    out.push("(".to_string());
    out.extend(cond.iter().cloned());
    out.push(")".to_string());
    out.push(";".to_string());
}

/// Rewrites `require(c, m);` and `if (c) revert ..;` into `require ( c' ) ;`.
pub fn unify_guards(toks: &[String]) -> Vec<String> {
    let mut out = Vec::with_capacity(toks.len());
    let mut i = 0;
    while i < toks.len() {
        let t = toks[i].as_str();
        if t == "require" && toks.get(i + 1).map(String::as_str) == Some("(") {
            if let Some(close) = matching(toks, i + 1) {
                if toks.get(close + 1).map(String::as_str) == Some(";") {
                    let args = split_at_top(&toks[i + 2..close], ",");
                    emit_require(&mut out, strip_parens(&args[0]));
                    i = close + 2;
                    continue;
                }
            }
        }
        if t == "if" && toks.get(i + 1).map(String::as_str) == Some("(") {
            if let Some(close) = matching(toks, i + 1) {
                let braced = toks.get(close + 1).map(String::as_str) == Some("{");
                let body = close + 1 + usize::from(braced);
                if let Some(end) = revert_stmt_end(toks, body) {
                    let end = if braced {
                        if toks.get(end).map(String::as_str) == Some("}") { Some(end + 1) } else { None }
                    } else {
                        Some(end)
                    };
                    if let Some(end) = end {
                        if toks.get(end).map(String::as_str) != Some("else") {
                            emit_require(&mut out, &negate(&toks[i + 2..close]));
                            i = end;
                            continue;
                        }
                    }
                }
            }
        }
        out.push(toks[i].clone());
        i += 1;
    }
    out
}

/// Tokens for the fuzzy stage: `tokenize`, plus guard unification in normalized mode.
/// `--exact` keeps identifiers and literals as written, so it keeps guards as written too.
pub fn tokenize_semantic(src: &str, mode: Mode, keep: Option<&HashSet<String>>) -> Vec<String> {
    let toks = tokenize_keeping(src, mode, keep);
    match mode {
        Mode::Normalized => unify_guards(&toks),
        Mode::Exact => toks,
    }
}

/// Canonical text for the exact (character-level) tier: comments gone,
/// whitespace gone except a single space where two words would otherwise
/// merge. Two sources that differ only in layout or comments give the same
/// string; anything else (names, literals, order) must match character for
/// character.
pub fn canonical(src: &str) -> String {
    let word = |c: char| c.is_ascii_alphanumeric() || c == '_' || c == '$';
    let mut out = String::new();
    for t in tokenize(src, Mode::Exact) {
        if let (Some(prev), Some(next)) = (out.chars().last(), t.chars().next()) {
            if word(prev) && word(next) {
                out.push(' ');
            }
        }
        out.push_str(&t);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_ignores_layout_and_comments_but_not_names() {
        let a = canonical("function f( uint x ) {\n  // c\n  return x; }");
        let b = canonical("function f(uint x){return x;}");
        let c = canonical("function f(uint y){return y;}");
        assert_eq!(a, b);
        assert_ne!(a, c);
        assert!(a.contains("uint x"), "words must stay separated: {a}");
    }

    #[test]
    fn strips_comments_and_whitespace() {
        let t = tokenize("a /* x */ = 1; // tail\nb", Mode::Exact);
        assert_eq!(t, ["a", "=", "1", ";", "b"]);
    }

    #[test]
    fn normalizes_identifiers_and_literals_but_keeps_keywords() {
        let t = tokenize("require(msg.sender == owner, \"no\");", Mode::Normalized);
        assert_eq!(
            t,
            ["require", "(", "msg", ".", "sender", "==", "ID", ",", "LIT", ")", ";"]
        );
    }

    #[test]
    fn sized_types_are_keywords() {
        let t = tokenize("uint256 x; bytes32 y;", Mode::Normalized);
        assert_eq!(t, ["uint256", "ID", ";", "bytes32", "ID", ";"]);
    }

    fn sem(src: &str) -> String {
        tokenize_semantic(src, Mode::Normalized, None).join(" ")
    }

    #[test]
    fn require_and_if_revert_become_one_shape() {
        let want = sem("require(a == b, \"msg\");");
        assert_eq!(want, "require ( ID == ID ) ;");
        assert_eq!(sem("if (a != b) revert Mismatch();"), want);
        assert_eq!(sem("if (a != b) { revert Mismatch(x, 1); }"), want);
        assert_eq!(sem("if (a != b) revert(\"no\");"), want);
        assert_eq!(sem("if (!(a == b)) revert Errors.Mismatch();"), want);
        assert_eq!(sem("require(a == b);"), want);
    }

    #[test]
    fn negation_follows_logic_not_just_the_operator() {
        assert_eq!(sem("require(a < b);"), sem("if (a >= b) revert E();"));
        assert_eq!(sem("require(a && b);"), sem("if (!a || !b) revert E();"));
        assert_eq!(sem("require(a || b);"), sem("if (!a && !b) revert E();"));
        assert_eq!(sem("require(ok(x));"), sem("if (!ok(x)) revert E();"));
        // different conditions must stay different: `<=` is not `==`
        assert_ne!(sem("require(a == b);"), sem("require(a <= b);"));
        assert_ne!(sem("require(a == b);"), sem("if (a == b) revert E();"));
    }

    #[test]
    fn guard_unification_leaves_unknown_shapes_alone() {
        // `else` after the revert, extra statements in the block, and the exact mode
        let keep = "if (a) revert E(); else { x = 1; }";
        assert_eq!(sem(keep), tokenize(keep, Mode::Normalized).join(" "));
        let two = "if (a) { y = 1; revert E(); }";
        assert_eq!(sem(two), tokenize(two, Mode::Normalized).join(" "));
        let ex = "if (a != b) revert E();";
        assert_eq!(tokenize_semantic(ex, Mode::Exact, None), tokenize(ex, Mode::Exact));
    }

    #[test]
    fn literals_added_or_removed_by_the_fix_stay_visible() {
        let keep = decisive_literals("f(x, 20); g(x, 64); h(x, 5);", "f(x, 20); f(y, 20); h(x, 5);");
        // 20 appears once vs twice, 64 once vs never; 5 is the same on both sides
        assert!(keep.contains("20") && keep.contains("64") && !keep.contains("5"));
        let t = |s: &str| tokenize_keeping(s, Mode::Normalized, Some(&keep)).join(" ");
        assert_eq!(t("a >= 20"), "ID >= 20");
        assert_ne!(t("a >= 20"), t("a >= 1"));
        assert_eq!(t("a >= 5"), t("a >= 1")); // other literals still collapse
    }

    #[test]
    fn canonical_text_is_not_touched_by_guard_unification() {
        assert_ne!(canonical("require(a == b);"), canonical("if (a != b) revert E();"));
    }

    #[test]
    fn handles_unterminated_input_without_panicking() {
        let _ = tokenize("/* open", Mode::Exact);
        let _ = tokenize("\"open", Mode::Exact);
        let _ = tokenize("x \u{0627}\u{0644} y", Mode::Exact);
    }
}
