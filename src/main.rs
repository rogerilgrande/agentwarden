//! agentwarden binary: a thin wrapper that runs the library entry point.

#![forbid(unsafe_code)]

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    agentwarden::run().await
}
