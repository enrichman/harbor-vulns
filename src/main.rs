mod goharbor;

use thiserror::Error;
use crate::goharbor::Client;

#[derive(Error, Debug)]
enum MyError {
    #[error("Error executing reqwest X.\nError: {0}")]
    HTTPError(#[from] reqwest::Error),
    #[error("error parsing")]
    JSONError(#[from] serde_json::Error),
}


#[tokio::main]
async fn main() -> Result<(), MyError> {
    println!("Hello, world!");

    let host = "https://demo.goharbor.io";
    let username = "harbor-demo-account";
    let password = "Password123";

    let client = Client::new(host, username, password)?;

    let project_name = "test-proj-demo";
    let repository_name = "nginx";
    let reference = "latest";


    let vulns = client.vulnerabilities(project_name, repository_name, reference).await?;

    println!("{:?}", vulns);

    Ok(())
}
