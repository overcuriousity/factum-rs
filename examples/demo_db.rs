//! Fills a database with a demo case, e.g. for screenshots: `FACTUM_DB=/tmp/demo.db cargo run --example demo_db`
//! Signs with the active GPG key of that database, if one is set.

use factum::signer::GnupgSigner;
use factum::{Db, Factum};

fn main() -> factum::Result<()> {
    let db = Db::open_default()?;
    let signer = GnupgSigner::new(&db, None);
    let factum = Factum::new(&db, &signer);
    let case_id = factum.create_case(
        "2026/041",
        "Ransomware at Müller GmbH",
        "Initial response, file server FS01",
    )?;
    let disk = factum.create_evidence(
        case_id,
        "FS01 system disk image",
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    )?;
    let memory = factum.create_evidence(case_id, "FS01 memory dump", "")?;
    factum.create_note(
        "Arrived on site, FS01 isolated from the network by the customer at 08:12 local time. #timeline",
        None,
        case_id,
    )?;
    let first = factum.create_note("Found suspicious binary C:\\Users\\Public\\svch0st.exe, beaconing to 185.220.101.4 and evil-cdn.example.com #malware", Some(disk), case_id)?;
    factum.correct_note(first, "Found suspicious binary C:\\Users\\Public\\svch0st.exe, beaconing to 185.220.101.47 and evil-cdn.example.com #malware")?;
    factum.create_note(
        "Ransom note README_RESTORE.txt in every share; contact mail recover@protonmail.example #ransomware",
        Some(disk),
        case_id,
    )?;
    let pinned = factum.create_note("Volatility: injected code in explorer.exe (PID 4120), MD5 of dump 9e107d9d372bb6826bd81d3542a419d6 #persistence", Some(memory), case_id)?;
    factum.pin_note(pinned)?;
    factum::tags::add_label(&db, pinned, "review")?;
    factum
        .create_note(
            "Long observation to check wrapping: "
                .to_string()
                .as_str()
                .to_owned()
                .as_str(),
            None,
            case_id,
        )
        .and_then(|_| {
            factum.create_note(
                &"The scheduled task \\Microsoft\\Windows\\Update\\Sync runs every 15 minutes. ".repeat(6),
                None,
                case_id,
            )
        })?;
    println!("Demo case #{case_id} created in {}", db.path.display());
    Ok(())
}
