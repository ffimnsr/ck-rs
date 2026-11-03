//! Read-only inspection, search, tree, and audit queries.

use std::collections::BTreeMap;

use chainkeeper_core::{
    AuditEvent, AuditQuery, AuthorityKind, AuthorityName, AuthorityRecord, CertificateRecord,
    ChainkeeperError, InspectReport, SearchQuery, Serial, TreeNode, TreeReport,
};

use crate::engine::Engine;

/// Maximum number of search results.
const MAX_SEARCH_LIMIT: usize = 10_000;
/// Maximum number of audit rows returned by one query.
pub const MAX_AUDIT_LIMIT: usize = 10_000;
/// Default number of audit rows returned.
pub const DEFAULT_AUDIT_LIMIT: usize = 100;

fn validate_search(query: &SearchQuery) -> Result<(), ChainkeeperError> {
    if query.limit == Some(0) {
        return Err(ChainkeeperError::validation("limit must be positive"));
    }
    if query.limit.is_some_and(|limit| limit > MAX_SEARCH_LIMIT) {
        return Err(ChainkeeperError::validation(format!(
            "limit must be {MAX_SEARCH_LIMIT} or less"
        )));
    }
    if query.text.as_ref().is_some_and(|text| text.len() > 512) {
        return Err(ChainkeeperError::validation(
            "search text must be 512 bytes or less",
        ));
    }
    if query.expires_within_days.is_some_and(|days| days > 36_500) {
        return Err(ChainkeeperError::validation(
            "expires_within_days must be 36500 or less",
        ));
    }
    Ok(())
}

/// Runs `ck inspect`.
pub fn inspect(engine: &Engine, serial: &Serial) -> Result<InspectReport, ChainkeeperError> {
    let record = if let Some(record) = engine.store.get_certificate(serial)? {
        record
    } else {
        let query = SearchQuery {
            text: Some(serial.to_string()),
            limit: Some(1),
            ..SearchQuery::default()
        };
        engine
            .index
            .query(&query)?
            .into_iter()
            .find(|record| &record.serial == serial)
            .ok_or_else(|| ChainkeeperError::not_found("certificate", serial.as_str()))?
    };
    let status = record.status(engine.now());
    let cert_pem = std::fs::read_to_string(engine.paths.root().join(&record.path)).ok();
    Ok(InspectReport {
        certificate: record,
        status,
        cert_pem,
        chain_pem: None,
    })
}

/// Runs `ck search`.
pub fn search(
    engine: &Engine,
    query: &SearchQuery,
) -> Result<Vec<CertificateRecord>, ChainkeeperError> {
    validate_search(query)?;
    engine.index.query(query)
}

/// Runs `ck tree`.
pub fn tree(engine: &Engine) -> Result<TreeReport, ChainkeeperError> {
    let authorities = engine.store.list_authorities()?;
    let by_name: BTreeMap<AuthorityName, AuthorityRecord> = authorities
        .iter()
        .cloned()
        .map(|record| (record.name.clone(), record))
        .collect();

    let roots: Vec<&AuthorityRecord> = authorities
        .iter()
        .filter(|record| record.kind == AuthorityKind::Root)
        .collect();
    if roots.is_empty() {
        return Err(ChainkeeperError::not_found("root authority", "root"));
    }
    if roots.len() > 1 {
        return Err(ChainkeeperError::Conflict(
            chainkeeper_core::ErrorDetail::new("repository has more than one root authority"),
        ));
    }
    if roots[0].parent.is_some() {
        return Err(ChainkeeperError::validation(
            "root authority must not declare a parent",
        ));
    }

    for record in &authorities {
        if record.kind != AuthorityKind::Root {
            let parent = record.parent.as_ref().ok_or_else(|| {
                ChainkeeperError::validation(format!("authority {} has no parent", record.name))
            })?;
            if !by_name.contains_key(parent) {
                return Err(ChainkeeperError::validation(format!(
                    "authority {} references missing parent {}",
                    record.name, parent
                )));
            }
        }
    }

    let mut children: BTreeMap<AuthorityName, Vec<AuthorityRecord>> = BTreeMap::new();
    for record in &authorities {
        if let Some(parent) = &record.parent {
            children
                .entry(parent.clone())
                .or_default()
                .push(record.clone());
        }
    }

    let mut visiting = Vec::new();
    let mut visited = std::collections::BTreeSet::new();
    let root = build_node(&roots[0].clone(), &children, &mut visiting, &mut visited)?;
    if let Some(unreachable) = authorities
        .iter()
        .find(|record| !visited.contains(&record.name))
    {
        return Err(ChainkeeperError::validation(format!(
            "authority {} is unreachable from the root and may form a cycle",
            unreachable.name
        )));
    }
    Ok(TreeReport { roots: vec![root] })
}

fn build_node(
    record: &AuthorityRecord,
    children: &BTreeMap<AuthorityName, Vec<AuthorityRecord>>,
    visiting: &mut Vec<AuthorityName>,
    visited: &mut std::collections::BTreeSet<AuthorityName>,
) -> Result<TreeNode, ChainkeeperError> {
    if visiting.contains(&record.name) {
        return Err(ChainkeeperError::validation(format!(
            "authority hierarchy contains a cycle at {}",
            record.name
        )));
    }
    visiting.push(record.name.clone());
    let mut nodes = Vec::new();
    if let Some(entries) = children.get(&record.name) {
        for child in entries {
            nodes.push(build_node(child, children, visiting, visited)?);
        }
    }
    visiting.pop();
    visited.insert(record.name.clone());
    nodes.sort_by(|left, right| left.name.cmp(&right.name));
    Ok(TreeNode {
        name: record.name.clone(),
        kind: record.kind,
        expires_at: Some(Engine::authority_expiry(record)),
        children: nodes,
    })
}

/// Runs `ck audit`.
pub fn audit(engine: &Engine, query: &AuditQuery) -> Result<Vec<AuditEvent>, ChainkeeperError> {
    let mut query = query.clone();
    match query.limit {
        Some(0) => {
            return Err(ChainkeeperError::validation("limit must be positive"));
        }
        Some(limit) if limit > MAX_AUDIT_LIMIT => {
            return Err(ChainkeeperError::validation(format!(
                "limit must be {MAX_AUDIT_LIMIT} or less"
            )));
        }
        Some(_) => {}
        None => query.limit = Some(DEFAULT_AUDIT_LIMIT),
    }
    engine.audit.list(&query)
}
