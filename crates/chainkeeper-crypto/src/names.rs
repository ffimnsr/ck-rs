//! Distinguished name encoding and decoding.

use chainkeeper_core::{ChainkeeperError, SubjectName};
use openssl::nid::Nid;
use openssl::x509::{X509NameBuilder, X509NameRef};

fn crypto<E: std::fmt::Display>(error: E) -> ChainkeeperError {
    ChainkeeperError::crypto(error.to_string())
}

/// Encodes a [`SubjectName`] as a DER distinguished name.
///
/// Attribute order is fixed as `CN, O, OU, C, ST, L, emailAddress`.
///
/// # Errors
///
/// Returns [`ChainkeeperError::Validation`] when the subject is invalid and
/// [`ChainkeeperError::Crypto`] when OpenSSL rejects an attribute.
pub fn to_der(subject: &SubjectName) -> Result<Vec<u8>, ChainkeeperError> {
    subject.validate()?;
    let mut builder = X509NameBuilder::new().map_err(crypto)?;
    builder
        .append_entry_by_nid(Nid::COMMONNAME, &subject.cn)
        .map_err(crypto)?;
    append_optional(
        &mut builder,
        Nid::ORGANIZATIONNAME,
        subject.organization.as_deref(),
    )?;
    append_optional(
        &mut builder,
        Nid::ORGANIZATIONALUNITNAME,
        subject.organizational_unit.as_deref(),
    )?;
    append_optional(&mut builder, Nid::COUNTRYNAME, subject.country.as_deref())?;
    append_optional(
        &mut builder,
        Nid::STATEORPROVINCENAME,
        subject.state.as_deref(),
    )?;
    append_optional(&mut builder, Nid::LOCALITYNAME, subject.locality.as_deref())?;
    append_optional(
        &mut builder,
        Nid::PKCS9_EMAILADDRESS,
        subject.email.as_deref(),
    )?;
    let name = builder.build();
    name.to_der().map_err(crypto)
}

fn append_optional(
    builder: &mut X509NameBuilder,
    nid: Nid,
    value: Option<&str>,
) -> Result<(), ChainkeeperError> {
    if let Some(value) = value {
        builder.append_entry_by_nid(nid, value).map_err(crypto)?;
    }
    Ok(())
}

/// Extracts one subject attribute from an OpenSSL distinguished name.
fn first_entry(name: &X509NameRef, nid: Nid) -> Option<String> {
    name.entries_by_nid(nid)
        .next()
        .and_then(|entry| entry.data().to_string().ok())
}

/// Renders a distinguished name with short attribute labels.
///
/// The output format (`CN=…, O=…`) is stable and used in certificate records.
#[must_use]
pub fn render(name: &X509NameRef) -> String {
    let mut parts = Vec::new();
    for entry in name.entries() {
        let nid = entry.object().nid();
        let label = match nid {
            Nid::COMMONNAME => "CN",
            Nid::ORGANIZATIONNAME => "O",
            Nid::ORGANIZATIONALUNITNAME => "OU",
            Nid::COUNTRYNAME => "C",
            Nid::STATEORPROVINCENAME => "ST",
            Nid::LOCALITYNAME => "L",
            Nid::PKCS9_EMAILADDRESS => "emailAddress",
            _ => continue,
        };
        if let Ok(value) = entry.data().to_string() {
            parts.push(format!("{label}={value}"));
        }
    }
    parts.join(", ")
}

/// Builds the default OCSP signer subject from its parent.
#[must_use]
pub fn ocsp_signer_subject(name: &str, parent: &X509NameRef) -> SubjectName {
    SubjectName {
        cn: name.to_owned(),
        organization: first_entry(parent, Nid::ORGANIZATIONNAME),
        organizational_unit: None,
        country: first_entry(parent, Nid::COUNTRYNAME),
        state: None,
        locality: None,
        email: None,
    }
}

#[cfg(test)]
mod tests {
    use chainkeeper_core::SubjectName;
    use openssl::nid::Nid;
    use openssl::x509::{X509Name, X509NameRef};

    use super::{crypto, first_entry, render, to_der};

    fn from_der(der: &[u8]) -> Result<SubjectName, chainkeeper_core::ChainkeeperError> {
        let name = X509Name::from_der(der).map_err(crypto)?;
        from_x509(&name)
    }

    fn from_x509(name: &X509NameRef) -> Result<SubjectName, chainkeeper_core::ChainkeeperError> {
        let cn = first_entry(name, Nid::COMMONNAME).ok_or_else(|| {
            chainkeeper_core::ChainkeeperError::validation("subject has no common name")
        })?;
        Ok(SubjectName {
            cn,
            organization: first_entry(name, Nid::ORGANIZATIONNAME),
            organizational_unit: first_entry(name, Nid::ORGANIZATIONALUNITNAME),
            country: first_entry(name, Nid::COUNTRYNAME),
            state: first_entry(name, Nid::STATEORPROVINCENAME),
            locality: first_entry(name, Nid::LOCALITYNAME),
            email: first_entry(name, Nid::PKCS9_EMAILADDRESS),
        })
    }

    #[test]
    fn subject_round_trips_in_canonical_order() {
        let mut subject = SubjectName::new("leaf.example.test").with_organization("Example");
        subject.country = Some("US".to_owned());
        subject.email = Some("ops@example.test".to_owned());
        let der = to_der(&subject).expect("encode");
        let parsed = from_der(&der).expect("decode");
        assert_eq!(parsed, subject);
    }

    #[test]
    fn render_uses_short_labels() {
        let subject = SubjectName::new("root").with_organization("Example");
        let der = to_der(&subject).expect("encode");
        let name = openssl::x509::X509Name::from_der(&der).expect("parse");
        assert_eq!(render(&name), "CN=root, O=Example");
        assert_eq!(from_x509(&name).expect("subject").cn, "root".to_owned());
    }
}
