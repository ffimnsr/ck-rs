//! Searchable selection shared by interactive commands.

use chainkeeper_core::{CertificateRecord, Serial};

use crate::error::CliError;
use crate::prompt::Prompter;

/// Filterable view over a list of values.
#[derive(Debug, Clone, Copy)]
pub struct Selector<T> {
    serial: fn(&T) -> String,
    fields: fn(&T) -> Vec<String>,
}

impl<T> Selector<T> {
    /// Builds a selector from a stable ordering key and searchable fields.
    #[must_use]
    pub const fn new(serial: fn(&T) -> String, fields: fn(&T) -> Vec<String>) -> Self {
        Self { serial, fields }
    }

    /// Filters `items` by a case-insensitive substring and orders them by
    /// serial. An empty query returns every item.
    #[must_use]
    pub fn filter<'a>(&self, query: &str, items: &'a [T]) -> Vec<&'a T> {
        let needle = query.trim().to_lowercase();
        let mut matched: Vec<&T> = items
            .iter()
            .filter(|item| {
                needle.is_empty()
                    || (self.fields)(item)
                        .iter()
                        .any(|field| field.to_lowercase().contains(&needle))
            })
            .collect();
        matched.sort_by_key(|item| (self.serial)(item));
        matched
    }

    /// Prompts for one item. Never blocks when the prompter is non-interactive.
    ///
    /// # Errors
    ///
    /// Returns [`CliError::Usage`] when not interactive or no item matches.
    pub fn select(
        &self,
        prompter: Prompter,
        message: &str,
        items: &[T],
        label: impl Fn(&T) -> String,
    ) -> Result<T, CliError>
    where
        T: Clone,
    {
        let ordered = self.filter("", items);
        let options = ordered
            .into_iter()
            .map(|item| (label(item), item.clone()))
            .collect();
        prompter.select(message, options)
    }
}

/// Selector for certificate records.
#[must_use]
pub fn certificates() -> Selector<CertificateRecord> {
    Selector::new(
        |record| record.serial.to_string(),
        |record| {
            let mut fields = vec![
                record.subject.cn.clone(),
                record.serial.to_string(),
                record.profile.to_string(),
            ];
            if let Some(email) = &record.subject.email {
                fields.push(email.clone());
            }
            for san in &record.sans {
                fields.push(san.value().to_owned());
            }
            fields
        },
    )
}

/// Stable ordering helper used by selectors.
#[must_use]
pub fn serial_key(serial: &Serial) -> String {
    serial.to_string()
}

#[cfg(test)]
mod tests {
    use chainkeeper_core::{
        AuthorityName, CertificateRecord, KeyAlgorithm, ProfileName, San, SubjectName,
    };
    use time::macros::datetime;

    use super::certificates;
    use crate::error::CliError;
    use crate::prompt::Prompter;

    fn record(serial: &str, cn: &str, profile: &str, sans: Vec<San>) -> CertificateRecord {
        CertificateRecord {
            serial: chainkeeper_core::Serial::new(serial).expect("serial"),
            subject: SubjectName::new(cn),
            issuer: "CN=Root".to_owned(),
            profile: ProfileName::new(profile).expect("profile"),
            authority: AuthorityName::new("tls").expect("authority"),
            algorithm: KeyAlgorithm::EcdsaP256,
            sans,
            ekus: Vec::new(),
            key_usages: Vec::new(),
            issued_at: datetime!(2024-01-01 00:00:00 UTC),
            expires_at: datetime!(2025-01-01 00:00:00 UTC),
            path: format!("certificates/active/{serial}.pem").into(),
            revoked_at: None,
            revocation_reason: None,
            replaces: None,
        }
    }

    #[test]
    fn filters_across_cn_san_serial_and_profile() {
        let selector = certificates();
        let items = vec![
            record("00FF", "api.example.test", "tls-server", Vec::new()),
            record(
                "0010",
                "mail.example.test",
                "smime",
                vec![San::Email("ops@example.test".to_owned())],
            ),
        ];
        for query in ["api", "ops@example", "0010", "smime"] {
            assert_eq!(selector.filter(query, &items).len(), 1, "{query}");
        }
        assert_eq!(selector.filter("example.test", &items).len(), 2);
        assert_eq!(selector.filter("missing", &items).len(), 0);
    }

    #[test]
    fn orders_by_serial() {
        let selector = certificates();
        let items = vec![
            record("00FF", "b", "tls-server", Vec::new()),
            record("0010", "a", "tls-server", Vec::new()),
        ];
        let ordered: Vec<String> = selector
            .filter("", &items)
            .into_iter()
            .map(|record| record.serial.to_string())
            .collect();
        assert_eq!(ordered, vec!["0010", "00FF"]);
    }

    #[test]
    fn non_interactive_selection_returns_usage_error() {
        let selector = certificates();
        let items = vec![record("0010", "a", "tls-server", Vec::new())];
        let error = selector
            .select(
                Prompter::new(false, false),
                "certificate",
                &items,
                |record| record.subject.cn.clone(),
            )
            .expect_err("non-interactive");
        assert!(matches!(error, CliError::Usage(_)));
        assert_eq!(error.exit_code(), 2);
    }
}
