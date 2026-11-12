//! Validate a certificate with certval against a trust store the binary contains, or verify a CMS
//! SignedData with certval-cms and validate its signers the same way.
//!
//! The three inputs are the target certificate (or the signed message), a store id naming which
//! linked community's trust anchors and CA certificates to use, and a JSON settings file holding
//! the policy the path is judged under. Everything else -- which anchors exist, which
//! intermediates are available, how they chain -- comes out of the store crates at link time.

use std::error::Error;
use std::path::Path;
use std::process::ExitCode;
use std::sync::Arc;

use clap::Parser;
use der::{Decode, DecodePem, Encode};
use x509_cert::certificate::{CertificateInner, Raw};

use certval::*;
use certval_cms::{CmsEnvironment, SignerPolicy, Vetting};
use certval_stores_core::{prepare_certval_environment, TrustStoreProvider};
use cms::content_info::ContentInfo;

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
    #[arg(short, long, conflicts_with = "signed")]
    target: Option<String>,

    /// CMS SignedData to verify, DER or PEM; each signer's certificate is validated as --target
    /// would be
    #[arg(long)]
    signed: Option<String>,

    /// The content of a detached --signed message
    #[arg(long, requires = "signed")]
    content: Option<String>,

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

    let result = match (&args.target, &args.signed) {
        (Some(target), None) => validate(&args, target).await,
        (None, Some(signed)) => verify_signed(&args, signed),
        _ => {
            eprintln!("--target or --signed is required unless --list-stores is given");
            return ExitCode::FAILURE;
        }
    };
    match result {
        Ok(true) => ExitCode::SUCCESS,
        Ok(false) => ExitCode::FAILURE,
        Err(e) => {
            eprintln!("{e}");
            ExitCode::FAILURE
        }
    }
}

/// Reads the settings file, saying which policy the run is judged under.
fn settings(args: &Args) -> Result<CertificationPathSettings> {
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
    Ok(read_settings(&args.settings)?)
}

/// The PkiEnvironment for the named store: its anchors and CA store from the linked provider
/// crates, plus any --chain certificates. Also returns whether the store carries anchors alone.
fn environment(args: &Args, cps: &CertificationPathSettings) -> Result<(PkiEnvironment, bool)> {
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

    prepare_certval_environment(&providers(), &mut pe, &args.store)?;

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
        cert_source.initialize(cps)?;
        cert_source.find_all_partial_paths(&pe, cps);
        pe.add_certificate_source(Box::new(cert_source));
    }

    Ok((pe, anchors_only))
}

/// Returns whether at least one path from the target to an anchor in the named store validated.
async fn validate(args: &Args, target: &str) -> Result<bool> {
    let cps = settings(args)?;
    let toi = cps.get_time_of_interest();
    let (pe, anchors_only) = environment(args, &cps)?;

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

/// Verifies a SignedData's signatures and validates each signer's certificate against the named
/// store, and returns whether every signer verified.
///
/// certval-cms does the CMS side: the message digest and content type attributes, each signature,
/// and, because settings are passed, a path from each signer's certificate to an anchor, with the
/// certificate permitting signing. The PkiEnvironment is the one --target uses, shared with the
/// CmsEnvironment, so the store decides whom the message can be trusted from.
fn verify_signed(args: &Args, signed: &str) -> Result<bool> {
    let cps = settings(args)?;
    let (pe, _) = environment(args, &cps)?;
    let mut env = CmsEnvironment::new();
    env.set_pki_environment(Arc::new(pe));

    let content_info = ContentInfo::from_der(&read_der(signed)?)?;
    let detached = args.content.as_ref().map(std::fs::read).transpose()?;

    let verified = match env.verify_signed_data(
        &content_info,
        detached.as_deref(),
        Some(&cps),
        SignerPolicy::All,
    ) {
        Ok(verified) => verified,
        Err(e) => {
            println!("not verified: {e}");
            return Ok(false);
        }
    };
    println!(
        "verified: {} octets of content, type {}",
        verified.content.len(),
        verified.content_type
    );
    for (i, signer) in verified.signers.iter().enumerate() {
        let status = match &signer.vetting {
            Vetting::Validated(cpr) => cpr
                .get_validation_status()
                .map(|s| format!("{s:?}"))
                .unwrap_or_else(|| String::from("no status")),
            _ => String::from("not validated"),
        };
        println!(
            "signer {i}: {}\n    path         {status}",
            name_to_string(signer.certificate.tbs_certificate().subject())
        );
    }
    Ok(true)
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

/// Reads a file as DER, converting from PEM when that is what the file holds.
fn read_der(filename: &str) -> Result<Vec<u8>> {
    let bytes = std::fs::read(filename)?;
    if bytes.starts_with(b"-----BEGIN") {
        Ok(der::pem::decode_vec(&bytes)?.1)
    } else {
        Ok(bytes)
    }
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
