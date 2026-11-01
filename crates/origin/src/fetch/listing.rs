//! The two paginated lists the release watcher reads: a repository's tags from
//! the GitHub API, and an image's referrer tags from the registry.
//!
//! A `Link` header is hostile input like the rest of a response, so its URL is
//! never requested. On GitHub it only says that there is a next page, whose
//! number is known. On the registry it may also give a cursor, which goes to the
//! same registry and the same path as one encoded query value. So a response
//! cannot send a request, or the token on it, anywhere else.

use std::collections::{BTreeMap, BTreeSet, HashSet};

use landfall_core::ids::{ImageDigest, ReleaseTag, RepoName};
use reqwest::Url;
use reqwest::header::{HeaderMap, LINK};
use serde::Deserialize;

use super::{
    FetchError, Fetched, Fetcher, MANIFEST_LIMIT, check_image, check_object_id, join, parse,
};

/// The most tags read of one list, counting every tag it names, whether it is
/// of interest or not. Past this the list is an error and not a shorter list: a
/// tag past the cap could be the second digest of a release.
pub const MAX_LISTED_TAGS: usize = 5_000;

/// The most pages read of one list, so that a server sending short pages for
/// ever is stopped as well. Fifty of GitHub's full pages hold [`MAX_LISTED_TAGS`].
const MAX_PAGES: usize = 100;

/// Tags asked for on a page of GitHub's list, its maximum.
const GITHUB_PAGE_SIZE: &str = "100";

/// Tags asked for on a page of the registry's list.
const REGISTRY_PAGE_SIZE: &str = "1000";

/// A tag of a repository and the git object its ref points at.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ListedTag {
    /// The tag.
    pub tag: ReleaseTag,
    /// The id of the object the ref names: the tag object of an annotated tag,
    /// which changes when the tag is signed again or moved, or the commit of a
    /// lightweight one. 40 lowercase hex digits.
    pub object: String,
}

/// One entry of `GET /repos/<repo>/git/matching-refs/tags`.
#[derive(Deserialize)]
struct MatchingRef {
    #[serde(rename = "ref")]
    name: String,
    object: RefObject,
}

#[derive(Deserialize)]
struct RefObject {
    sha: String,
}

/// `GET /v2/<image>/tags/list`. An image with no tags may say `null`.
#[derive(Deserialize)]
struct TagList {
    tags: Option<Vec<String>>,
}

/// The count of a list, refusing what goes past the cap.
fn counted(url: &Url, total: &mut usize, more: usize) -> Result<(), FetchError> {
    *total = total.saturating_add(more);
    if *total > MAX_LISTED_TAGS {
        return Err(FetchError::ListCap {
            url: url.to_string(),
            limit: MAX_LISTED_TAGS,
            what: "tags",
        });
    }
    Ok(())
}

fn too_many_pages(url: &Url) -> FetchError {
    FetchError::ListCap {
        url: url.to_string(),
        limit: MAX_PAGES,
        what: "pages",
    }
}

/// The target of the `rel="next"` link of a response, if it has one. RFC 8288,
/// as far as this needs: `<target>; param; param, <target>; param`. A target
/// holding a comma ends up cut short, which at worst loses a cursor.
fn next_link(headers: &HeaderMap) -> Option<&str> {
    headers
        .get_all(LINK)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(','))
        .find_map(|link| {
            let (target, params) = link.trim().strip_prefix('<')?.split_once('>')?;
            params
                .split(';')
                .any(|param| {
                    let param = param.trim().to_ascii_lowercase();
                    param == "rel=\"next\"" || param == "rel=next"
                })
                .then_some(target)
        })
}

/// The cursor in a next link: its `last` value. The target may be relative, and
/// nothing else of it is used.
fn cursor_of(base: &Url, target: &str) -> Option<String> {
    base.join(target)
        .ok()?
        .query_pairs()
        .find(|(key, _)| key == "last")
        .map(|(_, value)| value.into_owned())
}

/// A referrer tag's digest: exactly `sha256-` and 64 lowercase hex digits. A
/// cosign `.sig` or `.att` tag is not one.
fn referrer_digest(tag: &str) -> Option<ImageDigest> {
    let hex = tag.strip_prefix("sha256-")?;
    let valid = hex.len() == 64 && hex.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'));
    if valid {
        format!("sha256:{hex}").parse().ok()
    } else {
        None
    }
}

impl Fetcher {
    /// Every tag of `repo`, sorted by name. A ref whose name is not a valid
    /// release tag cannot be a release and is left out, but it counts.
    ///
    /// # Errors
    ///
    /// [`FetchError::ListCap`] past [`MAX_LISTED_TAGS`] tags or the page cap,
    /// [`FetchError::Malformed`] for an object id that is not one, and the
    /// transport, status and parsing errors.
    pub async fn list_release_tags(&self, repo: &RepoName) -> Result<Vec<ListedTag>, FetchError> {
        let mut segments = vec!["repos"];
        segments.extend(repo.as_ref().split('/'));
        segments.extend(["git", "matching-refs", "tags"]);
        let base = join(&self.endpoints.github_api, &segments)?;
        let mut tags = BTreeMap::new();
        let mut total = 0;
        for page in 1..=MAX_PAGES {
            let mut url = base.clone();
            url.query_pairs_mut()
                .append_pair("per_page", GITHUB_PAGE_SIZE)
                .append_pair("page", &page.to_string());
            let response = self.github_fetch(&url, MANIFEST_LIMIT).await?;
            let refs: Vec<MatchingRef> = parse(&url, &response.body)?;
            counted(&base, &mut total, refs.len())?;
            for entry in refs {
                check_object_id(&url, &entry.object.sha)?;
                let tag = entry
                    .name
                    .strip_prefix("refs/tags/")
                    .and_then(|name| name.parse::<ReleaseTag>().ok());
                if let Some(tag) = tag {
                    tags.insert(tag, entry.object.sha);
                }
            }
            if next_link(&response.headers).is_none() {
                return Ok(tags
                    .into_iter()
                    .map(|(tag, object)| ListedTag { tag, object })
                    .collect());
            }
        }
        Err(too_many_pages(&base))
    }

    /// Every digest of `image` that has a referrer tag, `sha256-<hex>`, sorted.
    /// Each may be for a release or for anything else: this says only that the
    /// tag exists, so what it refers to is still to be verified.
    ///
    /// # Errors
    ///
    /// [`FetchError::ListCap`] past [`MAX_LISTED_TAGS`] tags or the page cap,
    /// [`FetchError::Malformed`] for a cursor that comes round again, and the
    /// transport, status and parsing errors.
    pub async fn list_referrer_digests(&self, image: &str) -> Result<Vec<ImageDigest>, FetchError> {
        check_image(image)?;
        let token = self.registry_token(image).await?;
        let mut segments = vec!["v2"];
        segments.extend(image.split('/'));
        segments.extend(["tags", "list"]);
        let base = join(&self.endpoints.registry, &segments)?;

        let mut digests = BTreeSet::new();
        let mut total = 0;
        let mut seen_cursors = HashSet::new();
        let mut cursor: Option<String> = None;
        for _ in 0..MAX_PAGES {
            let mut url = base.clone();
            url.query_pairs_mut().append_pair("n", REGISTRY_PAGE_SIZE);
            if let Some(cursor) = &cursor {
                url.query_pairs_mut().append_pair("last", cursor);
            }
            let response = self
                .registry_get(&url, "application/json", Some(&token), MANIFEST_LIMIT)
                .await?;
            let tags = parse::<TagList>(&url, &response.body)?
                .tags
                .unwrap_or_default();
            counted(&base, &mut total, tags.len())?;
            digests.extend(tags.iter().filter_map(|tag| referrer_digest(tag)));

            let Some(next) = next_cursor(&base, &url, &response, &tags)? else {
                return Ok(digests.into_iter().collect());
            };
            if !seen_cursors.insert(next.clone()) {
                return Err(FetchError::Malformed {
                    url: url.to_string(),
                    reason: "the next page's cursor came round again".to_owned(),
                });
            }
            cursor = Some(next);
        }
        Err(too_many_pages(&base))
    }
}

/// Where the next page of a tag list starts, or `None` on the last page: the
/// cursor in the next link, or the page's last tag if the link has none, which
/// is what the distribution spec defines it to be.
fn next_cursor(
    base: &Url,
    url: &Url,
    response: &Fetched,
    tags: &[String],
) -> Result<Option<String>, FetchError> {
    let Some(target) = next_link(&response.headers) else {
        return Ok(None);
    };
    cursor_of(base, target)
        .or_else(|| tags.last().cloned())
        .map(Some)
        .ok_or_else(|| FetchError::Malformed {
            url: url.to_string(),
            reason: "an empty page says there is a next one, with no cursor".to_owned(),
        })
}

#[cfg(test)]
mod tests;
