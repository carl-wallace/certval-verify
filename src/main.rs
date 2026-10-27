//! Validate a certificate with certval against a trust store the binary contains.
//!
//! The three inputs are the target certificate, a store id naming which linked community's trust
//! anchors and CA certificates to use, and a JSON settings file holding the policy the path is
//! judged under. Everything else -- which anchors exist, which intermediates are available, how
//! they chain -- comes out of the store crates at link time.

use std::error::Error;
use std::path::Path;
use std::process::ExitCode;

use clap::Parser;
use der::{Decode, DecodePem, Encode};
use x509_cert::certificate::{CertificateInner, Raw};

use certval::*;
use certval_stores_core::{prepare_certval_environment, TrustStoreProvider};

type Result<T> = std::result::Result<T, Box<dyn Error>>;

/// The communities this binary can validate against. Adding one is a dependency and a line here;
/// each provider crate contains its own anchors and, where the community publishes enough to make
/// one, a CA store holding the intermediates and the partial paths among them.
fn providers() -> Vec<&'static dyn TrustStoreProvider> {
    vec![
        certval_stores_fpki::provider(),
        certval_stores_webpki_root_certs::provider(),
    ]
}

#[derive(Parser)]
#[command(
    version,
    about = "Validate a certificate against a trust store compiled into this binary"
)]
struct Args {
    /// Certificate to validate, DER or PEM
    #[arg(short, long)]
    target: Option<String>,

    /// Store id to validate against; see --list-stores
    #[arg(short, long, default_value = certval_stores_fpki::FPKI)]
    store: String,

    /// JSON-formatted certification path validation settings
    #[arg(long)]
    settings: Option<String>,

    /// Intermediate CA certificate to consider, DER or PEM; repeatable
    #[arg(short, long)]
    chain: Vec<String>,

    /// List the store ids this binary provides, then exit
    #[arg(long)]
    list_stores: bool,
}

#[tokio::main]
async fn main() -> ExitCode {
    env_logger::init();
    let args = Args::parse();

    if args.list_stores {
        for provider in providers() {
            for entry in provider.entries() {
                let anchors = entry.roots.len();
                let cas = if entry.cert_store_cbor.is_some() {
                    "with CA store"
                } else {
                    "anchors only"
                };
                println!(
                    "{:<20} {anchors:>4} anchors, {cas:<13} {}",
                    entry.id, entry.label
                );
            }
        }
        return ExitCode::SUCCESS;
    }

    let Some(target) = args.target.clone() else {
        eprintln!("--target is required unless --list-stores is given");
        return ExitCode::FAILURE;
    };

    match validate(&args, &target).await {
        Ok(true) => ExitCode::SUCCESS,
        Ok(false) => ExitCode::FAILURE,
        Err(e) => {
            eprintln!("{e}");
            ExitCode::FAILURE
        }
    }
}

/// Returns whether at least one path from the target to an anchor in the named store validated.
async fn validate(args: &Args, target: &str) -> Result<bool> {
    // The settings file is the policy input in full: the time of interest the path is judged at,
    // the initial policy set, whether revocation status is checked and how, name-constraint and
    // key-usage handling.
    //
    // certval reads a name that does not exist as defaults, which are to check revocation and to
    // fetch over the network. A typo that quietly turns those on is worth an error, and a run
    // without a file is worth saying so out loud.
    match &args.settings {
        Some(filename) if !Path::new(filename).exists() => {
            return Err(format!("settings file not found: {filename}").into())
        }
        Some(filename) => println!("settings: {filename}"),
        None => {
            println!("settings: certval defaults (revocation checked over the network)")
        }
    }
    let cps = read_settings(&args.settings)?;
    let toi = cps.get_time_of_interest();

    let mut pe = PkiEnvironment::default();
    pe.populate_5280_pki_environment();

    // Anchors and the CA store both come from the linked provider crates, so this call touches
    // neither the filesystem nor the network. Where the community publishes enough to build one,
    // the CA store also contains the partial paths among its certificates, which is what lets the
    // builder assemble candidate paths offline.
    let Some(entry) = providers()
        .iter()
        .flat_map(|p| p.entries())
        .find(|e| e.id == args.store)
    else {
        return Err(format!(
            "unknown store id {}; --list-stores prints the ids this binary contains",
            args.store
        )
        .into());
    };
    let anchors_only = entry.cert_store_cbor.is_none();

    let mut ta_source = TaSource::new();
    prepare_certval_environment(&providers(), &mut pe, &mut ta_source, &args.store)?;

    // Certificates named on the command line, for a store that ships anchors alone or a path that
    // runs through an intermediate the store predates.
    if !args.chain.is_empty() {
        let mut cert_source = CertSource::new();
        for filename in &args.chain {
            cert_source.push(CertFile {
                filename: filename.clone(),
                bytes: read_cert(filename)?,
            });
        }
        cert_source.initialize(&cps)?;
        cert_source.find_all_partial_paths(&pe, &cps);
        pe.add_certificate_source(Box::new(cert_source));
    }

    let mut target_cert = PDVCertificate::try_from(read_cert(target)?.as_slice())?;
    target_cert.parse_extensions(EXTS_OF_INTEREST);

    // A threshold of 0 collects every path the sources can assemble rather than stopping at the
    // first. More than one is the normal case in a cross-certified community, and they do not all
    // reach the same verdict.
    let mut paths = vec![];
    match pe.get_paths_for_target(&target_cert, &mut paths, 0, toi) {
        Ok(()) => {}
        // No certificate source at all: an anchors-only store and no --chain. certval reports that
        // as an error, but it is the same outcome as a source that found nothing.
        Err(certval::Error::Unrecognized) => {}
        Err(certval::Error::PathValidation(
            PathValidationStatus::InvalidNotAfterDate | PathValidationStatus::InvalidNotBeforeDate,
        )) => {
            println!("Target is not valid at the time of interest ({toi})");
            return Ok(false);
        }
        Err(e) => return Err(e.into()),
    }
    if paths.is_empty() {
        println!("No candidate paths to an anchor in {}", args.store);
        if anchors_only && args.chain.is_empty() {
            println!(
                "{} carries anchors only; name intermediate CA certificates with --chain",
                args.store
            );
        }
        return Ok(false);
    }

    let mut any_valid = false;
    for (i, path) in paths.iter_mut().enumerate() {
        let mut cpr = CertificationPathResults::new();
        let result = validate_path_rfc5280(&pe, &cps, path, &mut cpr);

        // A no-op unless the settings turned revocation checking on, and the reason this binary
        // has an async runtime at all: status comes from CRLs and OCSP responders over the network.
        if result.is_ok() {
            let _ = check_revocation(&pe, &cps, path, &mut cpr).await;
        }

        let status = cpr
            .get_validation_status()
            .map(|s| format!("{s:?}"))
            .unwrap_or_else(|| format!("{result:?}"));
        println!("path {i}: {status}");
        print_path(path);
        any_valid |= cpr.get_validation_status() == Some(PathValidationStatus::Valid);
    }
    Ok(any_valid)
}

/// Prints the path from its anchor down to the target, one subject per line.
fn print_path(path: &CertificationPath) {
    if let Ok(name) = get_trust_anchor_name(path.trust_anchor.decoded()) {
        println!("    anchor       {}", name_to_string(name));
    }
    for ca in &path.intermediates {
        println!(
            "    intermediate {}",
            name_to_string(ca.decoded().tbs_certificate().subject())
        );
    }
    println!(
        "    target       {}",
        name_to_string(path.target.decoded().tbs_certificate().subject())
    );
}

/// Reads a certificate file as DER, converting from PEM when that is what the file holds.
///
/// Decoded under the `Raw` profile so the bytes that go back out are the bytes that came in:
/// signatures are over the encoding as issued, and a re-encoding under a stricter profile is not
/// guaranteed to reproduce it.
fn read_cert(filename: &str) -> Result<Vec<u8>> {
    let bytes = std::fs::read(filename)?;
    if bytes.starts_with(b"-----BEGIN") {
        Ok(CertificateInner::<Raw>::from_pem(&bytes)?.to_der()?)
    } else {
        // Decoded and dropped to reject a file that is not a certificate here, where the filename
        // is still at hand to name in the error.
        CertificateInner::<Raw>::from_der(&bytes)?;
        Ok(bytes)
    }
}
