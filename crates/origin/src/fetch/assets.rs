//! A release's files, from the GitHub API.

use std::time::Duration;

use landfall_core::ids::{ReleaseTag, RepoName};
use landfall_core::text::shown;
use reqwest::Url;
use serde::Deserialize;

use super::http::{SameHost, Transfer, join, parse};
use super::{FetchError, Fetcher, MANIFEST_LIMIT, Service};

/// Cap on a release's binary.
pub const BINARY_LIMIT: usize = 64 * 1024 * 1024;

/// Cap on a release's file of checksums.
pub const SUMS_LIMIT: usize = 64 * 1024;

/// Total timeout for each request of a file's download, a redirect being another request:
/// the client's 30 s doesn't suit a binary.
pub(super) const ASSET_TIMEOUT: Duration = Duration::from_secs(600);

const OCTET_STREAM: &str = "application/octet-stream";

/// A file of a release, as GitHub lists it. Nothing here is trusted but as a way
/// of finding the file.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct ReleaseAsset {
    /// GitHub's id of the asset.
    pub id: u64,
    /// The file's name.
    pub name: String,
    /// The file's size in bytes, as GitHub says.
    pub size: u64,
}

#[derive(Deserialize)]
struct Release {
    tag_name: String,
    assets: Vec<ReleaseAsset>,
}

impl Fetcher {
    /// The files of the published release of `tag`:
    /// `GET /repos/<repo>/releases/tags/<tag>`.
    ///
    /// # Errors
    ///
    /// [`FetchError::NotFound`] when there is no such release,
    /// [`FetchError::Malformed`] when the answer is about another tag, and the
    /// transport and parsing errors.
    pub async fn release_assets(
        &self,
        repo: &RepoName,
        tag: &ReleaseTag,
    ) -> Result<Vec<ReleaseAsset>, FetchError> {
        let mut segments = vec!["repos"];
        segments.extend(repo.as_ref().split('/'));
        segments.extend(["releases", "tags"]);
        segments.extend(tag.as_ref().split('/'));
        let url = join(&self.endpoints.github_api, &segments)?;
        let response = self.github_fetch(&url, MANIFEST_LIMIT).await?;
        let release: Release = parse(&url, &response.body)?;
        if release.tag_name != tag.as_ref() as &str {
            return Err(FetchError::Malformed {
                url: url.to_string(),
                reason: format!("asked for release {tag}, got {}", shown(&release.tag_name)),
            });
        }
        Ok(release.assets)
    }

    /// The bytes of `asset`: `GET /repos/<repo>/releases/assets/<id>`, which redirects
    /// to a storage host. The token goes on that one request and no other: a redirect back
    /// to the API's host is refused, and a storage host's redirects carry none. No host
    /// is singled out for trust, as what a file is, is verified whoever serves it.
    ///
    /// Refused before reading if `asset` says it is over `limit`, and cut off while
    /// streaming at what it says it is, so the listing's size is the cap.
    ///
    /// # Errors
    ///
    /// [`FetchError::TooLarge`] when it is over either, [`FetchError::Malformed`] when
    /// it is shorter than the listing says, [`FetchError::Redirect`] for a redirect that
    /// is refused, and the transport errors.
    pub async fn release_asset(
        &self,
        repo: &RepoName,
        asset: &ReleaseAsset,
        limit: usize,
    ) -> Result<Vec<u8>, FetchError> {
        let url = self.asset_url(repo, asset)?;
        let size = usize::try_from(asset.size)
            .ok()
            .filter(|size| *size <= limit)
            .ok_or_else(|| FetchError::TooLarge {
                url: url.to_string(),
                limit,
            })?;
        let transfer = Transfer {
            accept: OCTET_STREAM,
            service: Service::GitHubApi,
            limit: size,
            timeout: Some(self.asset_timeout),
        };
        let body = self
            .get(
                &url,
                transfer,
                self.github_token.as_ref(),
                SameHost::Refused,
            )
            .await?
            .body;
        if body.len() != size {
            return Err(FetchError::Malformed {
                url: url.to_string(),
                reason: format!("{} bytes served, the release lists {size}", body.len()),
            });
        }
        Ok(body)
    }

    fn asset_url(&self, repo: &RepoName, asset: &ReleaseAsset) -> Result<Url, FetchError> {
        let id = asset.id.to_string();
        let mut segments = vec!["repos"];
        segments.extend(repo.as_ref().split('/'));
        segments.extend(["releases", "assets", id.as_str()]);
        join(&self.endpoints.github_api, &segments)
    }
}
