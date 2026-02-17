use anyhow::{Context, Result};
use reqwest::{Client, redirect::Policy};
use std::time::Duration;

pub(crate) fn build_probe_client(timeout_secs: u64, user_agent: &str) -> Result<Client> {
    let timeout_secs = timeout_secs.max(1);
    Client::builder()
        .redirect(Policy::none())
        .connect_timeout(Duration::from_secs(timeout_secs.min(8)))
        .timeout(Duration::from_secs(timeout_secs))
        .user_agent(user_agent)
        .build()
        .context("failed to build probe HTTP client")
}

pub(crate) fn build_data_client(timeout_secs: u64, user_agent: &str) -> Result<Client> {
    let timeout_secs = timeout_secs.max(1);
    Client::builder()
        .redirect(Policy::limited(8))
        .connect_timeout(Duration::from_secs(timeout_secs.min(8)))
        .timeout(Duration::from_secs(timeout_secs))
        .user_agent(user_agent)
        .build()
        .context("failed to build data HTTP client")
}
