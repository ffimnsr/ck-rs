//! `ck tree`.

use chainkeeper_core::{TreeNode, TreeReport};

use crate::commands::Context;
use crate::error::CliError;
use crate::format::time_text;

pub fn run(context: &Context<'_>) -> Result<u8, CliError> {
    let report = context.service.tree()?;
    if context.json {
        let value = context.json_value(&report)?;
        context.ui.json(&value)?;
        return Ok(0);
    }
    render(context, &report, "", true)?;
    Ok(0)
}

fn render(
    context: &Context<'_>,
    report: &TreeReport,
    prefix: &str,
    top: bool,
) -> Result<(), CliError> {
    for (index, node) in report.roots.iter().enumerate() {
        let last = index + 1 == report.roots.len();
        line(context, node, prefix, top, last)?;
    }
    Ok(())
}

fn line(
    context: &Context<'_>,
    node: &TreeNode,
    prefix: &str,
    top: bool,
    last: bool,
) -> Result<(), CliError> {
    let connector = if top {
        ""
    } else if last {
        "└── "
    } else {
        "├── "
    };
    let expires = node
        .expires_at
        .map_or_else(|| "unknown".to_owned(), time_text);
    context.ui.info(&format!(
        "{prefix}{connector}{} [{}] (expires {expires})",
        node.name,
        node.kind.as_str()
    ))?;
    let child_prefix = if top {
        String::new()
    } else if last {
        format!("{prefix}    ")
    } else {
        format!("{prefix}│   ")
    };
    for (index, child) in node.children.iter().enumerate() {
        line(
            context,
            child,
            &child_prefix,
            false,
            index + 1 == node.children.len(),
        )?;
    }
    Ok(())
}
