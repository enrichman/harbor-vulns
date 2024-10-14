use std::env;
use goharbor::Client;
use clap::{builder::PossibleValue, crate_authors, crate_description, crate_name, crate_version, Arg, ArgMatches, Command};
use dotenv::dotenv;

#[tokio::main]
async fn main() {
    dotenv().ok();

    let _username = env::var("USERNAME").unwrap_or("".to_string());

    let args = vec![
        Arg::new("log-level")
            .long("log-level")
            .value_name("LOG_LEVEL")
            .env("LOG_LEVEL")
            .default_value("info")
            .value_parser([
                PossibleValue::new("trace"),
                PossibleValue::new("debug"),
                PossibleValue::new("info"),
                PossibleValue::new("warn"),
                PossibleValue::new("error"),
            ])
            .help("Log level"),
    ];

    let cmd = Command::new(crate_name!())
        .author(crate_authors!())
        .version(crate_version!())
        .about(crate_description!())
        .subcommands(vec![
            vulns(),
        ],
        )
        .args(args);

    let matches = cmd.get_matches();
    let _matches = match matches.subcommand() {
        Some(("vulns", matches)) => { run_vulns(matches); }
        _ => unreachable!("clap should ensure we don't get here"),
    };

    let host = "https://demo.goharbor.io";
    let username = "harbor-demo-account";
    let password = "Password123";

    let client = Client::new(host, username, password).unwrap();

    let project_name = "test-proj-demo";
    let repository_name = "nginx";
    let reference = "latest";

    let vulns = client.vulnerabilities(project_name, repository_name, reference).await.unwrap();

    println!("{:?}", vulns);
}

fn vulns() -> Command {
    clap::command!("vulns")
        .arg(
            clap::arg!(--"manifest-path" <PATH>)
                .value_parser(clap::value_parser!(std::path::PathBuf)),
        )
        .arg(Arg::new("project-repo").required(true))
}

fn run_vulns(matches: &ArgMatches) {
    if let Some(project_repo) = matches.get_one::<String>("project-repo") {
        project_repo.split(":")
    }
}