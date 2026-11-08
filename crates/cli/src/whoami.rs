//! `landfall whoami`: who the controller takes this CLI for, and what it may do.

use std::io::{self, Write};

use landfall_api::MeView;
use tokio::runtime::Runtime;

use crate::api_client::ApiClient;
use crate::cli::CliError;
use crate::display::{safe, wire_name, write_json};

/// `GET /api/v1/me`, printed to `out` for a person, or as received with `json`.
pub(crate) fn run(
    runtime: &Runtime,
    client: &ApiClient,
    json: bool,
    out: &mut dyn Write,
) -> Result<(), CliError> {
    let text = runtime.block_on(client.get("/api/v1/me", &[]))?;
    if json {
        return write_json(out, &text).map_err(CliError::Output);
    }
    let me: MeView = ApiClient::typed(&text)?;
    render(&me, out).map_err(CliError::Output)
}

/// `me` for a person: who and by what, one line per grant, and where approvers sign.
fn render(me: &MeView, out: &mut dyn Write) -> io::Result<()> {
    writeln!(
        out,
        "{}, by {}",
        safe(me.principal.as_ref()),
        safe(&wire_name(&me.via))
    )?;
    for grant in &me.grants {
        let can: Vec<String> = grant.can.iter().map(wire_name).collect();
        writeln!(
            out,
            "{}: {}",
            safe(grant.deployment.as_ref()),
            safe(&can.join(", "))
        )?;
    }
    if let Some(url) = &me.approve_url {
        writeln!(out, "approvers sign at {}", safe(url))?;
    }
    Ok(())
}
