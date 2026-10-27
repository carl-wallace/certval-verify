# certval-verify

A certificate validator in one source file, using a trust store included in the binary.

[`certval`](https://github.com/carl-wallace/rust-pki/tree/main/certval) builds and validates RFC 5280
certification paths. The `certval_stores_*` crates, from
[certval-stores](https://github.com/carl-wallace/certval-stores), carry a
community's trust anchors and CA certificates as `include_bytes!` data. When used together, a
standards-compliant validator is fewer than 250 lines to read settings, prepare an environment, and build
and validate certification paths.

## Configuring certval to validate relative to a PKI

```rust
fn providers() -> Vec<&'static dyn TrustStoreProvider> {
    vec![
        certval_stores_fpki::provider(),
        certval_stores_webpki_root_certs::provider(),
    ]
}
```

That is it. No trust store to locate at startup, no anchors to read off disk, no bundle to ship
beside the binary and keep in sync with it. Each of those crates has its trust anchors compiled in, and `fpki` includes
CA certificates as well. What the `providers` function returns is what the binary can validate against.
Adding the DoD NIPR communities, the ECA program, or the Microsoft root set is a dependency and an additional
line here; dropping one is deleting a line, and the anchors leave the binary with it.

Everything else the tool does follows from this list. `--list-stores` reads and displays this list. The store ids
the `--store` option accepts come from it. 

Path building can be performed offline because a provider such as `fpki` contains the intermediates and the partial paths 
among them alongside the trust anchors. What a given binary trusts is fixed at compile time and auditable in the 
dependency graph, rather than assembled from the filesystem at run time.

## Running certval-verify

```bash
$ cargo run -- --list-stores
fpki                    1 anchors, with CA store U.S. Federal PKI (Common Policy CA G2)
webpki_root_certs     118 anchors, anchors only  Web PKI (Mozilla roots, TLS servers, via webpki-root-certs)

$ cargo run -- --store fpki --settings settings/offline.json --target examples/DOD_ID_CA-62.der
settings: settings/offline.json
path 0: Valid
    anchor       CN=Federal Common Policy CA G2,OU=FPKI,O=U.S. Government,C=US
    intermediate CN=Federal Bridge CA G4,OU=FPKI,O=U.S. Government,C=US
    intermediate CN=DoD Interoperability Root CA 2,OU=PKI,OU=DoD,O=U.S. Government,C=US
    intermediate CN=DoD Root CA 3,OU=PKI,OU=DoD,O=U.S. Government,C=US
    target       CN=DOD ID CA-62,OU=PKI,OU=DoD,O=U.S. Government,C=US
```

The command above shows successful validation given only a target for a certification path that
features five certificates, crosses the Federal Bridge from the federal PKI into the DoD PKI, and
requires no network. The target is a DoD issuing CA, included here as `examples/DOD_ID_CA-62.der` and published in the
`certval-stores` repository as `certval_stores_nipr/cas/prod/DOD_ID_CA-62.der`; a certificate it issues to a person chains the
same way, just one step further down. The store crate includes the trust anchor, the cross-certified 
mesh beneath it, and the partial paths among those certificates, so the builder assembles the path 
from data already linked into the binary. Additionally, `certval` is capable of dynamic path building, 
as illustrated in [`pittv3`](https://github.com/carl-wallace/rust-pki/tree/main/pittv3).

For stores that only include trust anchors, intermediate CA certificates can be provided on the
command line. The settings file in the example below sets `psTimeOfInterest` back to 2021, because
the server certificate in this example has long since expired:

```bash
$ cargo run -- --store webpki_root_certs --settings settings/2021.json --chain intermediate.der --target server.der
settings: settings/2021.json
path 0: Valid
    anchor       CN=DigiCert Global Root G2,OU=www.digicert.com,O=DigiCert Inc,C=US
    intermediate CN=DigiCert Global CA G2,O=DigiCert Inc,C=US
    target       CN=*.peg.a2z.com
```

## The three inputs

**A store id.** One of the ids `--list-stores` prints, which is to say one of the environments included in the
crates returned by the `providers()` function. A crate may serve more than one. For example, `certval_stores_fpki`
offers `fpki` and, behind a feature, the retired `fpki_legacy` mesh.

**A settings file.** A file containing JSON that can be deserialized using certval's `CertificationPathSettings`. Each
key is a `PS_*` constant in certval and each value is tagged with its type:

```json
{
  "psCheckRevocationStatus": { "Bool": true },
  "psInitialExplicitPolicyIndicator": { "Bool": true },
  "psInitialPolicySet": { "Strings": ["<the policy OID you require>"] },
  "psTimeOfInterest": { "TimeOfInterest": 1680000000 }
}
```

`settings/offline.json` validates with revocation checking and network retrieval turned off. `settings/revocation.json`
turns on CRL and OCSP checking, which is why the binary has an async runtime. The only difference
between those two runs is the filename on the command line.

`psTimeOfInterest` is a Unix timestamp and defaults to now. It can be used to validate certificates
relative to times in the past, as occurs when verifying timestamped code signer certificates.

**A target certificate.** A file containing a DER-encoded or PEM-encoded certificate.

## Using default settings

`--settings` is optional, and leaving it off is not the same as leaving the network alone:

```
$ cargo run -- --store fpki --target examples/DOD_ID_CA-62.der
settings: certval defaults (revocation checked over the network)
ERROR certval::revocation::crl] Failed to save CRL with: NotFound
path 0: Valid
    anchor       CN=Federal Common Policy CA G2,OU=FPKI,O=U.S. Government,C=US
    ...
```

Two things are happening there. Revocation checking is on by default, so the run reached out to the
CRL distribution points named in the path; and no download folder is set, so each fetched CRL is
discarded and the next run fetches it again.

`certval` supplies a default for every setting a file can carry, so an empty map is a complete,
usable policy. The ones worth knowing before running without a file:

| Setting | Default |
| --- | --- |
| `psTimeOfInterest` | now |
| `psRequireTaStore` | true |
| `psEnforceTrustAnchorValidity` | true |
| `psEnforceTrustAnchorConstraints` | false |
| `psInitialExplicitPolicyIndicator` | false |
| `psInitialPolicyMappingInhibitIndicator` | false |
| `psInitialInhibitAnyPolicyIndicator` | false |
| `psInitialPolicySet` | none set; policy processing is unconstrained |
| `psInitialPathLengthConstraint` | 15 |
| `psCheckRevocationStatus` | **true** |
| `psCheckCrls`, `psCheckCrlDpHttp` | **true** |
| `psCheckOcspFromAia` | **true** |
| `psRetrieveFromAiaSiaHttp` | **true** |
| `psOcspAiaNonceSetting` | `DoNotSendNonce` |
| `psCrlTimeout` | 60s |
| `psRevocationMaxAge` | 0 |
| `psMaxAiaSiaCerts` | 2000 |
| `psMaxCrlFetchBytes` / `psMaxOcspFetchBytes` / `psMaxAiaFetchBytes` | 100 MiB / 1 MiB / 4 MiB |
| `psForbidSelfSignedEE`, `psExtendedKeyUsagePath`, `psCborTaStore` | false |

So `settings/offline.json` is two deliberate `false` values against those defaults, plus `psRequireTaStore` stated
explicitly. Use this file when a run must not use the network.

`certval` reads a settings filename that does not exist as an absent one and uses defaults.
That turns a typo into a silently different policy, so this tool checks the name and exits with 
status 1 if an indicated file cannot be found.

```
$ cargo run -- --store fpki --settings /nope/typo.json --target examples/DOD_ID_CA-62.der
settings file not found: /nope/typo.json
```

## See `pittv3` for additional features

The [`pittv3`](https://github.com/carl-wallace/rust-pki/tree/main/pittv3) binaries, in the same
repository as `certval`, support fetching intermediates from AIA and SIA, caching a built graph across runs, 
diagnosing *why* each candidate path was rejected, exporting a run for comparison, and provide GUI and browser frontends.
All of that sits on the same `certval` calls this project uses. The browser version of `pittv3` demonstrates `certval` 
use in no-std contexts.
