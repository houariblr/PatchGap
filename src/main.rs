mod detect;
mod lexer;

use detect::{Patch, Tier, Verdict};
use lexer::Mode;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::exit;

const USAGE: &str = "\
patchgap: find Solidity files that still contain a known pre-patch snippet

USAGE:
    patchgap --old <file> --new <file> [OPTIONS] <path>...

    --old <file>    code before the fix (the vulnerable snippet)
    --new <file>    code after the fix
    --k <n>         shingle size in tokens (default 6)
    --exact         compare identifiers and literals as written
                    (default: normalized, renamed variables still match)
    --all           also list files that are patched or have no match

<path> may be .sol files or directories (searched recursively).
Exit code: 0 = nothing unpatched, 1 = at least one UNPATCHED file, 2 = usage error.
";

struct Args {
    old: PathBuf,
    new: PathBuf,
    k: usize,
    mode: Mode,
    all: bool,
    paths: Vec<PathBuf>,
}

fn parse_args() -> Result<Args, String> {
    let mut it = std::env::args().skip(1);
    let (mut old, mut new) = (None, None);
    let (mut k, mut mode, mut all) = (6usize, Mode::Normalized, false);
    let mut paths = Vec::new();
    while let Some(a) = it.next() {
        match a.as_str() {
            "-h" | "--help" => {
                print!("{USAGE}");
                exit(0);
            }
            "--old" => old = Some(PathBuf::from(it.next().ok_or("--old needs a file")?)),
            "--new" => new = Some(PathBuf::from(it.next().ok_or("--new needs a file")?)),
            "--k" => {
                k = it
                    .next()
                    .ok_or("--k needs a number")?
                    .parse()
                    .map_err(|_| "--k must be a positive integer")?;
                if k == 0 {
                    return Err("--k must be at least 1".into());
                }
            }
            "--exact" => mode = Mode::Exact,
            "--all" => all = true,
            s if s.starts_with("--") => return Err(format!("unknown option {s}")),
            _ => paths.push(PathBuf::from(a)),
        }
    }
    Ok(Args {
        old: old.ok_or("--old is required")?,
        new: new.ok_or("--new is required")?,
        k,
        mode,
        all,
        paths: if paths.is_empty() { return Err("give at least one path".into()) } else { paths },
    })
}

fn collect(path: &Path, out: &mut Vec<PathBuf>) {
    // Symlinks are not followed, so a crafted tree cannot send the scan elsewhere.
    let Ok(meta) = fs::symlink_metadata(path) else { return };
    if meta.is_dir() {
        let Ok(rd) = fs::read_dir(path) else { return };
        let mut entries: Vec<_> = rd.flatten().map(|e| e.path()).collect();
        entries.sort();
        for p in entries {
            collect(&p, out);
        }
    } else if meta.is_file() && path.extension().map_or(false, |e| e == "sol") {
        out.push(path.to_path_buf());
    }
}

fn main() {
    let args = match parse_args() {
        Ok(a) => a,
        Err(e) => {
            eprintln!("error: {e}\n\n{USAGE}");
            exit(2);
        }
    };
    let read = |p: &Path| {
        fs::read_to_string(p).unwrap_or_else(|e| {
            eprintln!("error: cannot read {}: {e}", p.display());
            exit(2);
        })
    };
    let patch = Patch::new(&read(&args.old), &read(&args.new), args.mode, args.k)
        .unwrap_or_else(|e| {
            eprintln!("error: {e}");
            exit(2);
        });

    let mut files = Vec::new();
    for p in &args.paths {
        collect(p, &mut files);
    }

    let mut rows = Vec::new();
    let mut skipped = 0usize;
    for f in &files {
        match fs::read_to_string(f) {
            Ok(src) => rows.push((f, patch.score(&src))),
            Err(_) => skipped += 1, // not valid UTF-8 or unreadable
        }
    }
    rows.sort_by(|a, b| {
        let rank = |v: Verdict| match v {
            Verdict::Unpatched => 0,
            Verdict::Ambiguous => 1,
            Verdict::Patched => 2,
            Verdict::NoMatch => 3,
        };
        rank(a.1.verdict)
            .cmp(&rank(b.1.verdict))
            .then((a.1.tier == Tier::Fuzzy).cmp(&(b.1.tier == Tier::Fuzzy)))
            .then(b.1.context.partial_cmp(&a.1.context).unwrap_or(std::cmp::Ordering::Equal))
    });

    let (mut unpatched, mut patched, mut ambiguous, mut nomatch) = (0, 0, 0, 0);
    for (path, s) in &rows {
        match s.verdict {
            Verdict::Unpatched => unpatched += 1,
            Verdict::Patched => patched += 1,
            Verdict::Ambiguous => ambiguous += 1,
            Verdict::NoMatch => nomatch += 1,
        }
        if args.all || matches!(s.verdict, Verdict::Unpatched | Verdict::Ambiguous) {
            println!(
                "{:<10} {:<5} ctx={:.2} old={:.2} new={:.2}  {}",
                s.verdict.label(),
                s.tier.label(),
                s.context,
                s.old,
                s.new,
                path.display()
            );
        }
    }
    let exact = rows.iter().filter(|r| r.1.tier == Tier::Exact).count();
    eprintln!(
        "scanned {} files ({exact} settled by exact match): {unpatched} unpatched, {ambiguous} ambiguous, {patched} patched, {nomatch} no-match{}",
        rows.len(),
        if skipped > 0 { format!(", {skipped} unreadable") } else { String::new() }
    );
    exit(if unpatched > 0 { 1 } else { 0 });
}
