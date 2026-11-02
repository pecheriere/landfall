//! Parsing and validating a fleet configuration.

use super::{Config, ConfigError, parse};
use crate::ids::DeploymentId;

mod approval;
mod checks;
mod parsing;
mod promotion;
mod signers;
mod validation;

const EXAMPLE: &str = r#"
[signers]
maintainer = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIKM1hoe1SDmmzbmxw5ZYTs7Vl0gw0s+eR1YJtTVyV9sn"

[approval]
rp_id = "landfall.example"
origin = "https://landfall.example"

[approvers]
operator = { credential_id = "Y3JlZGVudGlhbA", public_key = "cHVibGljLWtleQ" }

[[deployment]]
id = "app/prod"
repo = { name = "example/app", id = 1234, owner_id = 5678 }
host = "home-1"
compose = { dir = "/srv/compose/app", service = "app" }
origin = { workflow = ".github/workflows/release.yml", tags = "v*", signers = ["maintainer"] }
rule = { auto = "patch", approve = "minor", approvers = ["operator"] }
checks = [{ http = "/health", network = "app_app", port = 8080, expect = 200 }]
backup = { paths = ["state"], stop = true }

[[deployment]]
id = "app/staging"
repo = { name = "example/app", id = 1234, owner_id = 5678 }
host = "home-1"
compose = { dir = "/srv/compose/app-staging", service = "app" }
origin = { workflow = ".github/workflows/release.yml", tags = "v*", signers = ["maintainer"] }
rule = { auto = "any", approvers = ["operator"] }
checks = ["container-healthy"]
promote_to = { deployment = "app/prod", healthy_for = "24h" }

[[grant]]
principal = "operator"
deployments = ["app/prod", "app/staging"]
can = ["view", "request", "approve", "rollback"]
"#;

fn id(s: &str) -> DeploymentId {
    s.parse().unwrap()
}

fn parse_str(text: &str) -> Result<Config, ConfigError> {
    parse(text.as_bytes(), |_| Ok(()))
}

fn edited(from: &str, to: &str) -> String {
    assert!(EXAMPLE.contains(from), "fixture lacks {from:?}");
    EXAMPLE.replacen(from, to, 1)
}

fn fixture_key(file: &str) -> String {
    std::fs::read_to_string(format!(
        "{}/tests/fixtures/tag/{file}",
        env!("CARGO_MANIFEST_DIR")
    ))
    .unwrap()
}

fn with_signer(value: &str) -> String {
    EXAMPLE.replacen(
        &format!("maintainer = {:?}", fixture_key("signer.pub").trim_end()),
        &format!("maintainer = {value:?}"),
        1,
    )
}
