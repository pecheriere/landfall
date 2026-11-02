//! The rounds: one tick over the repositories, each kept from the others, and the
//! task that ticks.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use landfall_core::config::Config;
use tokio::sync::{Semaphore, watch};
use tokio::task::JoinSet;

use super::{
    REPOS_AT_ONCE, ReleaseSource, Stop, TickSummary, WatcherState, settle_whole_hold,
    watch_deployment,
};
use crate::agent_api::log;
use crate::store::Store;

const RAN_PAST_DEADLINE: &str = "looking at its repository ran past the deadline of a tick";

/// One tick of one repository's deployments, within its deadline.
async fn watch_repository<S: ReleaseSource>(
    store: Store,
    config: Arc<Config>,
    source: Arc<S>,
    state: Arc<WatcherState>,
    (repo, deployments): (u64, Vec<usize>),
) -> TickSummary {
    let mut summary = TickSummary::default();
    let now = match store.now() {
        Ok(now) => now,
        Err(error) => {
            log(&format!("watcher: {error}"));
            summary.failed = 1;
            return summary;
        }
    };
    if state.is_waiting(repo, now) {
        summary.backed_off = deployments.len();
        return summary;
    }
    // Each deployment goes first in its turn, so that one that keeps stopping the
    // repository's work does not keep the others from theirs.
    let mut rotated = deployments.clone();
    let turn = state.next_turn(repo);
    let places = rotated.len().max(1);
    rotated.rotate_left(turn % places);
    let work = async {
        for index in rotated {
            let d = &config.deployments()[index];
            match watch_deployment(&store, &config, source.as_ref(), d, state.cooldown_start).await
            {
                Ok((done, stop)) => {
                    summary.add(done);
                    if let Some(stop) = stop {
                        return Ok(Some(stop));
                    }
                }
                Err(error) => return Err(error),
            }
        }
        Ok(None)
    };
    let answer = tokio::time::timeout(state.repo_deadline, work).await;
    // A wait counts from when the work ended, which can be long after it began.
    let now = store.now().unwrap_or(now);
    match answer {
        Ok(Ok(None)) => state.succeeded(repo),
        Ok(Ok(Some(Stop::RateLimited(reset)))) => state.rate_limited(repo, reset, now),
        Ok(Ok(Some(Stop::Outage))) => state.failed(repo, now),
        Ok(Err(error)) => {
            log(&format!("watcher: repository id {repo}: {error}"));
            summary.failed += 1;
        }
        Err(_) => {
            log(&format!(
                "watcher: repository id {repo} ran past its deadline"
            ));
            state.failed(repo, now);
            summary.failed += 1;
            for index in deployments {
                let d = &config.deployments()[index];
                if let Err(error) = store
                    .set_hold((d.id(), d.host()), None, RAN_PAST_DEADLINE, false)
                    .await
                {
                    log(&format!("watcher: repository id {repo}: {error}"));
                }
            }
        }
    }
    summary
}

/// Holds every deployment for `reason`: nothing can be verified.
async fn hold_everything(store: &Store, config: &Config, reason: &str) -> TickSummary {
    let mut summary = TickSummary::default();
    for d in config.deployments() {
        let result = async {
            let (_, whole) = store.holds_of(d.id()).await?;
            settle_whole_hold(store, d, whole.as_ref(), Some(reason), &mut summary).await
        }
        .await;
        if let Err(error) = result {
            log(&format!("watcher: {error}"));
            summary.failed += 1;
        }
    }
    summary
}

/// One look at every configured deployment. A panic, an error or a hang in one
/// repository's work stays there.
pub async fn tick<S: ReleaseSource>(
    store: &Store,
    config: &Arc<Config>,
    source: &Arc<S>,
    state: &Arc<WatcherState>,
) -> TickSummary {
    // Before anything that needs the network, which may be away. It only costs this one
    // thing to fail: the next tick, or the next look at the request, ends it.
    if let Err(error) = store.settle_expired_requests().await {
        log(&format!(
            "watcher: ending requests past their time: {error}"
        ));
    }
    if let Err(reason) = source.prepare().await {
        return hold_everything(store, config, &reason).await;
    }
    let mut repositories: BTreeMap<u64, Vec<usize>> = BTreeMap::new();
    for (index, d) in config.deployments().iter().enumerate() {
        repositories.entry(d.repo().id()).or_default().push(index);
    }
    let permits = Arc::new(Semaphore::new(REPOS_AT_ONCE));
    let mut tasks = JoinSet::new();
    for repository in repositories {
        let work = watch_repository(
            store.clone(),
            Arc::clone(config),
            Arc::clone(source),
            Arc::clone(state),
            repository,
        );
        let permits = Arc::clone(&permits);
        tasks.spawn(async move {
            // Never closed, so this always gets one.
            let _permit = permits.acquire_owned().await;
            work.await
        });
    }
    let mut summary = TickSummary::default();
    while let Some(joined) = tasks.join_next().await {
        match joined {
            Ok(done) => summary.add(done),
            Err(error) => {
                log(&format!("watcher: a repository's work stopped: {error}"));
                summary.failed += 1;
            }
        }
    }
    summary
}

/// Ends when `stop` says so, or when nobody is left to say it.
async fn until_stopped(stop: &mut watch::Receiver<bool>) {
    drop(stop.wait_for(|stop| *stop).await);
}

/// Ticks every `interval` until `stop` says so, then lets go of whatever is in
/// flight: dropping it rolls back any transaction, and the next start looks again.
pub async fn run<S: ReleaseSource>(
    store: Store,
    config: Arc<Config>,
    source: Arc<S>,
    interval: Duration,
    mut stop: watch::Receiver<bool>,
) {
    let state = Arc::new(WatcherState::looking_every(interval));
    loop {
        let job = tokio::spawn({
            let (store, config, source, state) = (
                store.clone(),
                Arc::clone(&config),
                Arc::clone(&source),
                Arc::clone(&state),
            );
            async move { tick(&store, &config, &source, &state).await }
        });
        let abort = job.abort_handle();
        tokio::select! {
            joined = job => {
                if let Err(error) = joined {
                    log(&format!("watcher: a tick stopped: {error}"));
                }
            }
            () = until_stopped(&mut stop) => {
                abort.abort();
                return;
            }
        }
        tokio::select! {
            () = tokio::time::sleep(interval) => {}
            () = until_stopped(&mut stop) => return,
        }
    }
}
