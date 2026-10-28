//! X.509 signing and verification through gpgsm, with a throwaway CA (skipped without gpgsm or openssl).

mod common;

use common::GpgsmHome;
use factum::container::x509::Gpgsm;

fn home() -> Option<(GpgsmHome, Gpgsm)> {
    let Some(home) = GpgsmHome::new() else {
        eprintln!("skipped: gpgsm or openssl is not installed");
        return None;
    };
    let gpgsm = Gpgsm::new(Some(home.path()));
    Some((home, gpgsm))
}

#[test]
fn lists_the_signing_certificate() {
    let Some((home, gpgsm)) = home() else { return };
    assert!(gpgsm.available());
    let certs = gpgsm.list_secret_certs();
    assert_eq!(certs.len(), 1);
    assert_eq!(certs[0].fingerprint, home.leaf_fingerprint);
    assert!(certs[0].subject.contains("CN=Examiner One"), "{}", certs[0].subject);
    assert_eq!(certs[0].issuer, "CN=Factum Test Root");
}

#[test]
fn sign_and_verify_with_trusted_root() {
    let Some((home, gpgsm)) = home() else { return };
    home.trusted();
    let signature = gpgsm.sign_detached(&home.leaf_fingerprint, b"the turtle").unwrap();
    assert!(signature.starts_with("-----BEGIN SIGNED MESSAGE-----"), "{signature}");
    let check = gpgsm.verify_detached(&signature, b"the turtle");
    assert!(check.valid && check.trusted && check.valid_at_signing, "{check:?}");
    assert!(
        check.signer_subject.as_deref().unwrap_or("").contains("Examiner One"),
        "{check:?}"
    );
    assert_eq!(check.root_fingerprint.as_deref(), Some(home.root_fingerprint.as_str()));
    assert!(check.signed_utc.is_some());
    assert!(check.status.contains("revocation not checked"), "{}", check.status);
    // the examiner's keybox gained nothing, its trust list nothing
    let listing = home.gpgsm(&["--with-colons", "--list-keys"], &[]).unwrap();
    assert_eq!(String::from_utf8_lossy(&listing.stdout).matches("\nfpr:").count(), 2);
}

#[test]
fn untrusted_root_fails_with_root_named() {
    let Some((home, gpgsm)) = home() else { return };
    home.trusted();
    let signature = gpgsm.sign_detached(&home.leaf_fingerprint, b"data").unwrap();
    home.untrusted();
    let check = gpgsm.verify_detached(&signature, b"data");
    assert!(check.valid && !check.trusted, "{check:?}");
    assert_eq!(check.root_fingerprint.as_deref(), Some(home.root_fingerprint.as_str()));
    assert_eq!(check.root_subject.as_deref(), Some("CN=Factum Test Root"));
    // verifying did not mark the root trusted
    assert!(!home.path().join("trustlist.txt").exists());
}

#[test]
fn signing_is_refused_while_the_root_is_untrusted() {
    let Some((home, gpgsm)) = home() else { return };
    let error = gpgsm.sign_detached(&home.leaf_fingerprint, b"data").unwrap_err();
    assert!(error.contains("not trusted"), "{error}");
    assert!(!home.path().join("trustlist.txt").exists());
}

#[test]
fn tampered_data_is_invalid() {
    let Some((home, gpgsm)) = home() else { return };
    home.trusted();
    let signature = gpgsm.sign_detached(&home.leaf_fingerprint, b"data").unwrap();
    let check = gpgsm.verify_detached(&signature, b"other data");
    assert!(!check.valid, "{check:?}");
}

#[test]
fn chain_without_root_is_refused() {
    let Some((home, gpgsm)) = home() else { return };
    let chain = gpgsm.chain(&home.leaf_fingerprint, &[]).unwrap();
    assert_eq!(chain.matches("-----BEGIN CERTIFICATE-----").count(), 2);
    assert!(!chain.contains("Issuer ...:"));
    let output = home.gpgsm(&["--delete-keys", &home.root_fingerprint], &[]).unwrap();
    assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
    let error = gpgsm.chain(&home.leaf_fingerprint, &[]).unwrap_err();
    assert!(error.contains("Factum Test Root"), "{error}");
    let chain = gpgsm.chain(&home.leaf_fingerprint, &[home.file("root.pem")]).unwrap();
    assert_eq!(chain.matches("-----BEGIN CERTIFICATE-----").count(), 2);
}

#[test]
fn signing_with_the_root_only_in_a_chain_file() {
    let Some((home, gpgsm)) = home() else { return };
    home.trusted();
    let output = home.gpgsm(&["--delete-keys", &home.root_fingerprint], &[]).unwrap();
    assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
    let (signature, chain) = gpgsm
        .sign_with_chain(&home.leaf_fingerprint, b"data", &[home.file("root.pem")])
        .unwrap();
    assert_eq!(chain.matches("-----BEGIN CERTIFICATE-----").count(), 2);
    let check = gpgsm.verify_detached(&signature, b"data");
    assert!(check.valid && check.trusted, "{check:?}");
    // trust still comes only from the trust list
    let list = std::fs::read_to_string(home.path().join("trustlist.txt")).unwrap();
    assert_eq!(list.lines().count(), 1);
}
