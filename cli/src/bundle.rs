//! `mnr bundle` — mint keys and write `witness-bundle/2` files.
//!
//! The format is specified in `BUNDLE_SCHEMA.md` §4; the encoding and signing
//! live in `mnr-bundle`. This module is the operator-facing part: it reads a key
//! file and a whole-log file, refuses to overwrite either output, and prints the
//! two public keys a recipient has to pin.

use mnr_bundle::{
    export, from_seed_hex, generate, public_hex, random_hex, seed_hex, ExportRequest, Log, Scope,
};
use std::collections::HashMap;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::time::{SystemTime, UNIX_EPOCH};

pub fn cmd_bundle(args: &[String]) -> i32 {
    let result = match args.first().map(String::as_str) {
        Some("keygen") => keygen(&args[1..]),
        Some("export") => export_bundle(&args[1..]),
        _ => {
            eprintln!(
                "usage: mnr bundle <keygen|export>\n  \
                 mnr bundle keygen --out <seed-file>\n  \
                 mnr bundle export --log <entries.ndjson> --out <bundle.ndjson> \\\n      \
                 --scope <case|log> --node-key <file> --exporter-key <file> \\\n      \
                 --department <name> --node-id <id> [--case <number>] [--agency <name>] \\\n      \
                 [--seal <id>] [--actor <who>] [--role <role>] \\\n      \
                 [--generated-at <RFC3339>] [--bundle-id <id>]"
            );
            return 2;
        }
    };
    match result {
        Ok(()) => 0,
        Err((code, message)) => {
            eprintln!("{message}");
            code
        }
    }
}

fn keygen(args: &[String]) -> Result<(), (i32, String)> {
    let flags = parse_flags(args, &["--out"]).map_err(usage)?;
    let out = need(&flags, "--out")?;

    let (seed, key) = generate().map_err(|error| (1, error.to_string()))?;
    // The seed is created with its final mode, not chmod'ed afterwards, so it is
    // never readable by another user even briefly.
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options
        .open(&out)
        .map_err(|error| (1, format!("cannot create {out}: {error}")))?;
    file.write_all(format!("{}\n", seed_hex(&seed)).as_bytes())
        .map_err(|error| (1, format!("cannot write {out}: {error}")))?;
    file.sync_all()
        .map_err(|error| (1, format!("cannot sync {out}: {error}")))?;

    println!("wrote seed      {out} (mode 0600, never commit it)");
    println!("public key      {}", public_hex(&key));
    println!("pin it as       --pin {}", public_hex(&key));
    Ok(())
}

fn export_bundle(args: &[String]) -> Result<(), (i32, String)> {
    let flags = parse_flags(
        args,
        &[
            "--log",
            "--out",
            "--scope",
            "--node-key",
            "--exporter-key",
            "--case",
            "--department",
            "--agency",
            "--seal",
            "--node-id",
            "--actor",
            "--role",
            "--generated-at",
            "--bundle-id",
        ],
    )
    .map_err(usage)?;

    let log_path = need(&flags, "--log")?;
    let out = need(&flags, "--out")?;
    let scope = match flags.get("--scope").map(String::as_str) {
        Some("case") => Scope::Case,
        Some("log") => Scope::Log,
        _ => return Err(usage("--scope must be 'case' or 'log'")),
    };
    if scope == Scope::Case && !flags.contains_key("--case") {
        return Err(usage("--scope case requires --case <number>"));
    }

    let node = load_key(&need(&flags, "--node-key")?)?;
    let exporter = load_key(&need(&flags, "--exporter-key")?)?;

    let log_bytes =
        fs::read(&log_path).map_err(|error| (1, format!("cannot read {log_path}: {error}")))?;
    let log = Log::parse(&log_bytes).map_err(|error| (1, error.to_string()))?;

    let generated_at = flags
        .get("--generated-at")
        .cloned()
        .unwrap_or_else(now_rfc3339);
    let bundle_id = match flags.get("--bundle-id") {
        Some(id) => id.clone(),
        None => {
            let suffix = random_hex(4).map_err(|error| (1, error.to_string()))?;
            format!("BUNDLE-{}-{suffix}", compact_day(unix_now()))
        }
    };

    let mut request = ExportRequest::new(scope);
    request.bundle_id = bundle_id;
    request.generated_at = generated_at;
    request.case_number = flags.get("--case").cloned().unwrap_or_default();
    request.department = flags.get("--department").cloned().unwrap_or_default();
    request.agency = flags.get("--agency").cloned().unwrap_or_default();
    request.seal = flags.get("--seal").cloned().unwrap_or_default();
    request.node_id = flags.get("--node-id").cloned().unwrap_or_default();
    request.export_actor = flags.get("--actor").cloned().unwrap_or_default();
    request.export_role = flags.get("--role").cloned().unwrap_or_default();

    let bytes = export(&log, &request, &node, &exporter).map_err(|error| (1, error.to_string()))?;

    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&out)
        .map_err(|error| {
            (
                1,
                format!(
                    "cannot create {out}: {error}\n\
                     a bundle is never overwritten — an issued bundle is evidence, \
                     so export to a new path"
                ),
            )
        })?;
    file.write_all(&bytes)
        .map_err(|error| (1, format!("cannot write {out}: {error}")))?;
    file.sync_all()
        .map_err(|error| (1, format!("cannot sync {out}: {error}")))?;

    let entries = bytes.iter().filter(|byte| **byte == b'\n').count() - 1;
    println!("bundle          {out} ({} B)", bytes.len());
    println!(
        "scope           {} — {entries} entr{}, head {} leaves",
        scope.as_str(),
        if entries == 1 { "y" } else { "ies" },
        log.len()
    );
    println!("head root       {}", log.root_hex());
    println!("pin exporter    {}", public_hex(&exporter));
    println!("pin node        {}", public_hex(&node));
    Ok(())
}

fn load_key(path: &str) -> Result<mnr_bundle::SigningKey, (i32, String)> {
    let text = fs::read_to_string(path)
        .map_err(|error| (1, format!("cannot read key file {path}: {error}")))?;
    from_seed_hex(&text).map_err(|error| (1, error.to_string()))
}

fn parse_flags(
    args: &[String],
    known: &[&'static str],
) -> Result<HashMap<&'static str, String>, String> {
    let mut values = HashMap::new();
    let mut iter = args.iter();
    while let Some(flag) = iter.next() {
        let value = iter
            .next()
            .ok_or_else(|| format!("missing value for {flag}"))?;
        let key = known
            .iter()
            .find(|candidate| **candidate == flag.as_str())
            .ok_or_else(|| format!("unknown argument {flag}"))?;
        values.insert(*key, value.clone());
    }
    Ok(values)
}

fn need(
    flags: &HashMap<&'static str, String>,
    name: &'static str,
) -> Result<String, (i32, String)> {
    flags
        .get(name)
        .cloned()
        .ok_or_else(|| usage(format!("missing {name}")))
}

fn usage(message: impl Into<String>) -> (i32, String) {
    (2, message.into())
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}

/// `YYYY-MM-DDTHH:MM:SSZ`, computed without a date library.
fn now_rfc3339() -> String {
    rfc3339(unix_now())
}

fn rfc3339(seconds: u64) -> String {
    let days = (seconds / 86_400) as i64;
    let rest = seconds % 86_400;
    let (year, month, day) = civil_from_days(days);
    format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}Z",
        rest / 3_600,
        (rest % 3_600) / 60,
        rest % 60
    )
}

fn compact_day(seconds: u64) -> String {
    let (year, month, day) = civil_from_days((seconds / 86_400) as i64);
    format!("{year:04}{month:02}{day:02}")
}

/// Howard Hinnant's `civil_from_days`: days since 1970-01-01 to a Gregorian date.
fn civil_from_days(days: i64) -> (i64, u32, u32) {
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let day_of_era = z - era * 146_097;
    let year_of_era =
        (day_of_era - day_of_era / 1_460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let year = year_of_era + era * 400;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_prime = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * month_prime + 2) / 5 + 1;
    let month = if month_prime < 10 {
        month_prime + 3
    } else {
        month_prime - 9
    };
    let year = if month <= 2 { year + 1 } else { year };
    (year, month as u32, day as u32)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn timestamps_match_known_epoch_values() {
        assert_eq!(rfc3339(0), "1970-01-01T00:00:00Z");
        assert_eq!(rfc3339(1_709_164_800), "2024-02-29T00:00:00Z");
        assert_eq!(rfc3339(1_778_596_200), "2026-05-12T14:30:00Z");
        assert_eq!(compact_day(1_792_886_400), "20261025");
    }

    #[test]
    fn flags_are_strict_about_names_and_values() {
        let args = ["--log", "a.ndjson", "--out", "b.ndjson"].map(String::from);
        let parsed = parse_flags(&args, &["--log", "--out"]).unwrap();
        assert_eq!(parsed["--log"], "a.ndjson");
        assert!(parse_flags(&["--log".to_string()], &["--log"]).is_err());
        assert!(parse_flags(&["--nope".to_string(), "x".to_string()], &["--log"]).is_err());
    }
}
