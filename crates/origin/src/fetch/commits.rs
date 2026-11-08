//! The commits between two release commits, as GitHub's compare lists them.
//!
//! Compare is exact: every commit reachable from the head and not from the base,
//! merged branches included, oldest first. It also carries each changed file's patch,
//! which no endpoint leaves out, so each page is streamed under
//! [`COMPARE_PAGE_LIMIT`] and its `files` are skipped as it parses. Everything read
//! is hostile text: a commit id must be one, a summary is quoted and cut, and a
//! login that isn't one is dropped. The author is the login GitHub attributes by the
//! commit's email, which nothing verifies.

use landfall_core::ids::{CommitSha, RepoName};
use landfall_core::text::quoted;
use reqwest::header::HeaderMap;
use serde::Deserialize;

use super::http::{join, parse};
use super::{FetchError, Fetcher, RATELIMIT_REMAINING, RATELIMIT_RESET};

/// Cap on one page of a comparison: its patches can be large, and a page over it is
/// [`ComparePage::TooLarge`].
pub const COMPARE_PAGE_LIMIT: usize = 8 * 1024 * 1024;

/// Commits asked for on a page of a comparison, GitHub's maximum.
pub const COMPARE_PER_PAGE: u8 = 100;

/// The most commits kept of one comparison: the newest ones.
pub const KEPT_COMMITS: usize = 100;

/// The most characters of a commit's first line kept, before quoting.
pub const COMMIT_SUMMARY_CHARS: usize = 200;

/// GitHub's own name for a comparison of more than it will compute.
const UNPROCESSABLE: u16 = 422;

/// The longest login GitHub allows.
const LOGIN_MAX_CHARS: usize = 39;

/// How the head relates to the base.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CompareStatus {
    /// The base is an ancestor of the head.
    Ahead,
    /// They are the same commit.
    Identical,
    /// The head is an ancestor of the base.
    Behind,
    /// Neither is an ancestor of the other.
    Diverged,
}

impl CompareStatus {
    fn parse(text: &str) -> Option<Self> {
        match text {
            "ahead" => Some(Self::Ahead),
            "identical" => Some(Self::Identical),
            "behind" => Some(Self::Behind),
            "diverged" => Some(Self::Diverged),
            _ => None,
        }
    }
}

/// One commit of a comparison, its text made safe to keep.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ListedCommit {
    /// Its id.
    pub sha: CommitSha,
    /// The first line of its message, quoted, at most [`COMMIT_SUMMARY_CHARS`]
    /// characters of it.
    pub summary: String,
    /// The login GitHub attributes it to by its email, unverified; `None` when there
    /// is none or it isn't a GitHub login.
    pub author: Option<String>,
}

/// One page of a comparison.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ComparePage {
    /// The page, as GitHub lists it.
    Listed {
        /// How the head relates to the base.
        status: CompareStatus,
        /// Every commit of the comparison, not only this page's.
        total: u64,
        /// This page's commits, in GitHub's order: oldest first.
        commits: Vec<ListedCommit>,
        /// GitHub's `x-ratelimit-remaining`, if it said.
        rate_remaining: Option<u32>,
        /// GitHub's `x-ratelimit-reset`, when its window ends, in Unix seconds, if it
        /// said. Like the rest of the answer it is hostile: whoever acts on it bounds it.
        rate_reset: Option<i64>,
    },
    /// The page is over [`COMPARE_PAGE_LIMIT`], or GitHub answered 422: the comparison
    /// is too large to list. [`compare_url`] is where to read it. Neither keeps the
    /// answer's headers, so it says nothing of GitHub's rate limit: the next listed page
    /// does.
    TooLarge,
}

/// GitHub's page comparing `base` and `head`, for a person to read, built only from
/// the validated repository name and commit ids.
#[must_use]
pub fn compare_url(repo: &RepoName, base: &CommitSha, head: &CommitSha) -> String {
    format!("https://github.com/{repo}/compare/{base}...{head}")
}

/// `GET /repos/<repo>/compare/<base>...<head>`, as far as it is read. Anything else
/// in it, `files` above all, is skipped as it parses and never kept.
#[derive(Deserialize)]
struct CompareBody {
    status: String,
    total_commits: u64,
    commits: Vec<CompareCommit>,
}

#[derive(Deserialize)]
struct CompareCommit {
    sha: String,
    commit: CommitDetail,
    author: Option<Account>,
}

#[derive(Deserialize)]
struct CommitDetail {
    message: String,
}

#[derive(Deserialize)]
struct Account {
    login: Option<String>,
}

/// Whether `login` fits GitHub's login grammar, `[A-Za-z0-9-]{1,39}`.
fn is_login(login: &str) -> bool {
    (1..=LOGIN_MAX_CHARS).contains(&login.len())
        && login
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-')
}

/// The first line of `message`, quoted and cut.
fn summary(message: &str) -> String {
    quoted(message.lines().next().unwrap_or(""), COMMIT_SUMMARY_CHARS)
}

/// GitHub's count of requests left, if it is a number.
fn rate_remaining(headers: &HeaderMap) -> Option<u32> {
    headers
        .get(RATELIMIT_REMAINING)?
        .to_str()
        .ok()?
        .trim()
        .parse()
        .ok()
}

/// GitHub's end of its rate-limit window, if it is a number of Unix seconds.
fn rate_reset(headers: &HeaderMap) -> Option<i64> {
    headers
        .get(RATELIMIT_RESET)?
        .to_str()
        .ok()?
        .trim()
        .parse()
        .ok()
}

impl Fetcher {
    /// Page `page` of GitHub's comparison of `base` and `head` in `repo`, with
    /// [`COMPARE_PER_PAGE`] commits a page and the token if there is one.
    ///
    /// # Errors
    ///
    /// [`FetchError::Malformed`] for a status this doesn't know, a commit id that
    /// isn't one or more commits than a page holds, and the transport, status
    /// (rate limits included) and parsing errors. A page too large to list is not an
    /// error but [`ComparePage::TooLarge`].
    pub async fn compare_page(
        &self,
        repo: &RepoName,
        base: &CommitSha,
        head: &CommitSha,
        page: u32,
    ) -> Result<ComparePage, FetchError> {
        let range = format!("{base}...{head}");
        let mut segments = vec!["repos"];
        segments.extend(repo.as_ref().split('/'));
        segments.extend(["compare", range.as_str()]);
        let mut url = join(&self.endpoints.github_api, &segments)?;
        url.query_pairs_mut()
            .append_pair("per_page", &COMPARE_PER_PAGE.to_string())
            .append_pair("page", &page.to_string());
        let fetched = match self.github_fetch(&url, COMPARE_PAGE_LIMIT).await {
            Ok(fetched) => fetched,
            Err(
                FetchError::TooLarge { .. }
                | FetchError::Status {
                    status: UNPROCESSABLE,
                    ..
                },
            ) => {
                return Ok(ComparePage::TooLarge);
            }
            Err(error) => return Err(error),
        };
        let malformed = |reason: String| FetchError::Malformed {
            url: url.to_string(),
            reason,
        };
        let body: CompareBody = parse(&url, &fetched.body)?;
        let status = CompareStatus::parse(&body.status).ok_or_else(|| {
            malformed(format!(
                "comparison status {} is none of ahead, identical, behind or diverged",
                quoted(&body.status, 32)
            ))
        })?;
        if body.commits.len() > usize::from(COMPARE_PER_PAGE) {
            return Err(malformed(format!(
                "a page of {} commits, of at most {COMPARE_PER_PAGE} asked for",
                body.commits.len()
            )));
        }
        let commits = body
            .commits
            .into_iter()
            .map(|entry| {
                let sha = entry.sha.parse().map_err(|_| {
                    malformed(format!(
                        "commit id {} is not 40 lowercase hex digits",
                        quoted(&entry.sha, 48)
                    ))
                })?;
                Ok(ListedCommit {
                    sha,
                    summary: summary(&entry.commit.message),
                    author: entry
                        .author
                        .and_then(|account| account.login)
                        .filter(|login| is_login(login)),
                })
            })
            .collect::<Result<_, FetchError>>()?;
        Ok(ComparePage::Listed {
            status,
            total: body.total_commits,
            commits,
            rate_remaining: rate_remaining(&fetched.headers),
            rate_reset: rate_reset(&fetched.headers),
        })
    }
}
