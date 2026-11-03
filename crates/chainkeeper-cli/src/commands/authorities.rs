//! Authority commands.

use chainkeeper_core::{
    AuthorityKind, AuthorityName, AuthorityRecord, CreateAuthorityRequest, CreateOcspSignerRequest,
    KeyAlgorithm, SubjectName, TreeNode, TreeReport,
};

use crate::cli::{
    IntermediateCreateArgs, IntermediateInspectArgs, OcspSignerCreateArgs, RootCreateArgs,
};
use crate::commands::Context;
use crate::error::CliError;
use crate::format::time_text;

const ALLOWED_INTERMEDIATES: [&str; 4] = ["tls", "smime", "codesign", "ocsp"];

pub fn root(context: &Context<'_>, args: &RootCreateArgs) -> Result<u8, CliError> {
    let mut subject = SubjectName::new(
        args.cn
            .clone()
            .unwrap_or_else(|| "Chainkeeper Root CA".to_owned()),
    );
    subject.organization.clone_from(&args.org);
    subject.country.clone_from(&args.country);

    let record = context.service.create_root(&CreateAuthorityRequest {
        name: AuthorityName::new("root").map_err(|error| CliError::usage(error.to_string()))?,
        kind: AuthorityKind::Root,
        parent: None,
        subject,
        algorithm: KeyAlgorithm::from(args.algorithm),
        validity_days: args.validity_days,
        path_len: 1,
    })?;
    render_authority(context, &record)
}

pub fn intermediate(context: &Context<'_>, args: &IntermediateCreateArgs) -> Result<u8, CliError> {
    if !ALLOWED_INTERMEDIATES.contains(&args.name.as_str()) {
        return Err(CliError::usage(format!(
            "intermediate name must be one of {}",
            ALLOWED_INTERMEDIATES.join(", ")
        )));
    }
    let name = AuthorityName::new(args.name.clone())
        .map_err(|error| CliError::usage(error.to_string()))?;
    let parent = AuthorityName::new(args.parent.clone())
        .map_err(|error| CliError::usage(error.to_string()))?;
    let record = context
        .service
        .create_intermediate(&CreateAuthorityRequest {
            name,
            kind: AuthorityKind::Intermediate,
            parent: Some(parent),
            subject: SubjectName::new(args.cn.clone().unwrap_or_else(|| args.name.clone())),
            algorithm: KeyAlgorithm::from(args.algorithm),
            validity_days: args.validity_days,
            path_len: 0,
        })?;
    render_authority(context, &record)
}

pub fn inspect(context: &Context<'_>, args: &IntermediateInspectArgs) -> Result<u8, CliError> {
    let tree = context.service.tree()?;
    let mut nodes = Vec::new();
    flatten(&tree, &mut nodes);
    nodes.retain(|node| node.kind == AuthorityKind::Intermediate);

    let node = match &args.name {
        Some(name) => {
            let name = AuthorityName::new(name.clone())
                .map_err(|error| CliError::usage(error.to_string()))?;
            nodes
                .into_iter()
                .find(|node| node.name == name)
                .ok_or_else(|| {
                    CliError::Operation(chainkeeper_core::ChainkeeperError::not_found(
                        "intermediate",
                        name.as_str(),
                    ))
                })?
        }
        None => context.prompt.select(
            "Intermediate",
            nodes
                .into_iter()
                .map(|node| (node.name.to_string(), node))
                .collect(),
        )?,
    };

    if context.json {
        let value = context.json_value(&node)?;
        context.ui.json(&value)?;
        return Ok(0);
    }
    context.ui.table(&["FIELD", "VALUE"], &node_rows(node))?;
    Ok(0)
}

pub fn ocsp_signer(context: &Context<'_>, args: &OcspSignerCreateArgs) -> Result<u8, CliError> {
    let subject = args.cn.clone().map(SubjectName::new);
    let record = context
        .service
        .create_ocsp_signer(&CreateOcspSignerRequest {
            name: AuthorityName::new("ocsp-signer")
                .map_err(|error| CliError::usage(error.to_string()))?,
            parent: AuthorityName::new("ocsp")
                .map_err(|error| CliError::usage(error.to_string()))?,
            subject,
            algorithm: KeyAlgorithm::EcdsaP256,
            validity_days: args.validity_days,
        })?;
    render_authority(context, &record)
}

fn render_authority(context: &Context<'_>, record: &AuthorityRecord) -> Result<u8, CliError> {
    if context.json {
        let value = context.json_value(record)?;
        context.ui.json(&value)?;
        return Ok(0);
    }
    let rows = vec![
        vec!["name".to_owned(), record.name.to_string()],
        vec!["kind".to_owned(), record.kind.as_str().to_owned()],
        vec![
            "parent".to_owned(),
            record
                .parent
                .as_ref()
                .map_or_else(|| "none".to_owned(), ToString::to_string),
        ],
        vec!["algorithm".to_owned(), record.algorithm.as_str().to_owned()],
        vec!["validity_days".to_owned(), record.validity_days.to_string()],
        vec!["path_len".to_owned(), record.path_len.to_string()],
        vec![
            "cert_path".to_owned(),
            record.cert_path.display().to_string(),
        ],
        vec![
            "chain_path".to_owned(),
            record.chain_path.display().to_string(),
        ],
        vec!["created_at".to_owned(), time_text(record.created_at)],
    ];
    context.ui.table(&["FIELD", "VALUE"], &rows)?;
    Ok(0)
}

fn node_rows(node: &TreeNode) -> Vec<Vec<String>> {
    vec![
        vec!["name".to_owned(), node.name.to_string()],
        vec!["kind".to_owned(), node.kind.as_str().to_owned()],
        vec![
            "expires_at".to_owned(),
            node.expires_at
                .map_or_else(|| "unknown".to_owned(), time_text),
        ],
        vec!["children".to_owned(), node.children.len().to_string()],
    ]
}

fn flatten<'a>(tree: &'a TreeReport, nodes: &mut Vec<&'a TreeNode>) {
    for node in &tree.roots {
        visit(node, nodes);
    }
}

fn visit<'a>(node: &'a TreeNode, nodes: &mut Vec<&'a TreeNode>) {
    nodes.push(node);
    for child in &node.children {
        visit(child, nodes);
    }
}
