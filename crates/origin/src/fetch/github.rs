//! Signed tag objects and commits, from the GitHub API.

use landfall_core::ids::{CommitSha, ReleaseTag, RepoName};
use reqwest::header::{ACCEPT, AUTHORIZATION};
use reqwest::{RequestBuilder, Url};
use serde::Deserialize;
use sha1_checked::Digest as _;
use sha1_checked::Sha1;

use super::http::{Fetched, join, parse, send};
use super::{
    FetchError, Fetcher, GITHUB_ACCEPT, GITHUB_API_VERSION, MAX_TAG_DEPTH, Service,
    TAG_OBJECT_LIMIT, hex,
};

impl Fetcher {
    /// The raw signed tag object for `tag`: the bytes `git cat-file tag`
    /// prints, rebuilt from GitHub's signed payload and signature.
    ///
    /// # Errors
    ///
    /// [`FetchError::LightweightTag`] when the tag is not a tag object,
    /// [`FetchError::NotSigned`] when it carries no signature,
    /// [`FetchError::ObjectId`] when the bytes do not hash to the tag
    /// object's id, and the transport and parsing errors.
    pub async fn tag_object(
        &self,
        repo: &RepoName,
        tag: &ReleaseTag,
    ) -> Result<Vec<u8>, FetchError> {
        let reference = self.tag_ref(repo, tag).await?;
        match reference.kind.as_str() {
            "tag" => {}
            "commit" => return Err(FetchError::LightweightTag { tag: tag.clone() }),
            other => {
                return Err(FetchError::ObjectType {
                    tag: tag.clone(),
                    found: other.to_owned(),
                });
            }
        }
        let object = self.git_tag(repo, &reference.sha).await?;
        let Some(Verification {
            payload: Some(payload),
            signature: Some(signature),
        }) = object.verification
        else {
            return Err(FetchError::NotSigned { tag: tag.clone() });
        };
        let mut raw = payload.into_bytes();
        raw.extend_from_slice(signature.as_bytes());
        let computed =
            git_tag_id(&raw).ok_or_else(|| FetchError::Sha1Collision { tag: tag.clone() })?;
        if computed != reference.sha {
            return Err(FetchError::ObjectId {
                expected: reference.sha,
                computed,
            });
        }
        Ok(raw)
    }

    /// The commit `tag` points at, peeling annotated tag objects. For
    /// deployments that do not require signed tags.
    ///
    /// # Errors
    ///
    /// [`FetchError::ObjectType`] when the tag ends at a tree or blob,
    /// [`FetchError::TagDepth`] for a chain of too many tag objects, and the
    /// transport and parsing errors.
    pub async fn tag_commit(
        &self,
        repo: &RepoName,
        tag: &ReleaseTag,
    ) -> Result<CommitSha, FetchError> {
        let mut object = self.tag_ref(repo, tag).await?;
        let mut followed = 0;
        loop {
            match object.kind.as_str() {
                "commit" => {
                    return object.sha.parse().map_err(|_| FetchError::Malformed {
                        url: self.endpoints.github_api.to_string(),
                        reason: format!(
                            "commit id {:?} is not 40 lowercase hex digits",
                            object.sha
                        ),
                    });
                }
                "tag" if followed == MAX_TAG_DEPTH => {
                    return Err(FetchError::TagDepth { tag: tag.clone() });
                }
                "tag" => {
                    object = self.git_tag(repo, &object.sha).await?.object;
                    followed += 1;
                }
                other => {
                    return Err(FetchError::ObjectType {
                        tag: tag.clone(),
                        found: other.to_owned(),
                    });
                }
            }
        }
    }

    /// `GET /repos/<repo>/git/ref/tags/<tag>`: the object the tag ref names.
    async fn tag_ref(&self, repo: &RepoName, tag: &ReleaseTag) -> Result<GitObject, FetchError> {
        let mut segments = vec!["repos"];
        segments.extend(repo.as_ref().split('/'));
        segments.extend(["git", "ref", "tags"]);
        segments.extend(tag.as_ref().split('/'));
        let url = join(&self.endpoints.github_api, &segments)?;
        let body = self.github_get(&url).await?;
        let reference: GitRef = parse(&url, &body)?;
        if reference.name != format!("refs/tags/{tag}") {
            return Err(FetchError::Malformed {
                url: url.to_string(),
                reason: format!("asked for refs/tags/{tag}, got {:?}", reference.name),
            });
        }
        check_object_id(&url, &reference.object.sha)?;
        Ok(reference.object)
    }

    /// `GET /repos/<repo>/git/tags/<sha>`: the tag object `sha`.
    async fn git_tag(&self, repo: &RepoName, sha: &str) -> Result<GitTag, FetchError> {
        let mut segments = vec!["repos"];
        segments.extend(repo.as_ref().split('/'));
        segments.extend(["git", "tags", sha]);
        let url = join(&self.endpoints.github_api, &segments)?;
        let body = self.github_get(&url).await?;
        let object: GitTag = parse(&url, &body)?;
        if object.sha != sha {
            return Err(FetchError::Malformed {
                url: url.to_string(),
                reason: format!("asked for tag object {sha}, got {:?}", object.sha),
            });
        }
        check_object_id(&url, &object.object.sha)?;
        Ok(object)
    }

    /// A GET to the GitHub API, with the token when there is one.
    async fn github_get(&self, url: &Url) -> Result<Vec<u8>, FetchError> {
        Ok(self.github_fetch(url, TAG_OBJECT_LIMIT).await?.body)
    }

    /// [`github_get`](Self::github_get) with its headers, and a cap of `limit`.
    pub(super) async fn github_fetch(
        &self,
        url: &Url,
        limit: usize,
    ) -> Result<Fetched, FetchError> {
        let request = self.github_request(url, GITHUB_ACCEPT);
        send(request, Service::GitHubApi, url, limit).await
    }

    /// A GET to the GitHub API asking for `accept`, with the token when there is one.
    pub(super) fn github_request(&self, url: &Url, accept: &str) -> RequestBuilder {
        let mut request = self
            .client
            .get(url.clone())
            .header(ACCEPT, accept)
            .header("x-github-api-version", GITHUB_API_VERSION);
        if let Some(token) = &self.github_token {
            request = request.header(AUTHORIZATION, token.clone());
        }
        request
    }
}

/// The git object id of a tag object with content `raw`, or `None` when the
/// bytes carry a SHA-1 collision attack.
fn git_tag_id(raw: &[u8]) -> Option<String> {
    checked_sha1(&[format!("tag {}\0", raw.len()).as_bytes(), raw])
}

/// The SHA-1 of `parts` concatenated, as lowercase hex, or `None` when
/// collision detection finds a collision attack (SHAttered-style) in them.
pub(super) fn checked_sha1(parts: &[&[u8]]) -> Option<String> {
    let mut hasher = Sha1::new();
    for part in parts {
        hasher.update(part);
    }
    let result = hasher.try_finalize();
    (!result.has_collision()).then(|| hex(result.hash()))
}

/// Refuses an object id that is not 40 lowercase hex digits (SHA-1; GitHub
/// does not host SHA-256 repositories).
pub(super) fn check_object_id(url: &Url, sha: &str) -> Result<(), FetchError> {
    if sha.len() == 40 && sha.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')) {
        Ok(())
    } else {
        Err(FetchError::Malformed {
            url: url.to_string(),
            reason: format!("object id {sha:?} is not 40 lowercase hex digits"),
        })
    }
}

#[derive(Deserialize)]
struct GitRef {
    #[serde(rename = "ref")]
    name: String,
    object: GitObject,
}

#[derive(Deserialize)]
struct GitObject {
    sha: String,
    #[serde(rename = "type")]
    kind: String,
}

#[derive(Deserialize)]
struct GitTag {
    sha: String,
    object: GitObject,
    verification: Option<Verification>,
}

/// GitHub's view of a tag's signature: the object bytes before the
/// signature, and the signature. Both are null for an unsigned tag.
#[derive(Deserialize)]
struct Verification {
    payload: Option<String>,
    signature: Option<String>,
}
