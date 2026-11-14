//! The operator commands print their report on stdout and nothing else, so
//! it can be piped or saved: their logs go to stderr, and `aws_config`'s
//! credential lines, which print the access key ID, stay out unless
//! `RUST_LOG` asks for them.

use axum::http::StatusCode;
use axum::response::IntoResponse;

const ACCESS_KEY_ID: &str = "AKIDOPERATOROUTPUTTEST";
const HASH: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

/// A loopback S3 holding no object: every GET is 404 `NoSuchKey`.
async fn empty_s3() -> String {
    let app = axum::Router::new().fallback(|| async {
        (
            StatusCode::NOT_FOUND,
            "<Error><Code>NoSuchKey</Code><Message>none</Message></Error>",
        )
            .into_response()
    });
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    tokio::spawn(async move { axum::serve(listener, app).await.ok() });
    url
}

/// `release-owner` of a hash with no owner record, against [`empty_s3`],
/// with the credentials in a profile file (the provider that logs them),
/// `RUST_LOG` as given. Its exit status, stdout and stderr.
async fn release_owner(rust_log: Option<&str>) -> (bool, String, String) {
    let endpoint = empty_s3().await;
    let dir = tempfile::tempdir().unwrap();
    let config = dir.path().join("config.toml");
    std::fs::write(
        &config,
        format!(
            "[s3]\nbucket = \"b\"\nregion = \"us-east-1\"\n\
             endpoint_url = \"{endpoint}\"\nforce_path_style = true\n"
        ),
    )
    .unwrap();
    std::fs::write(dir.path().join("config"), "").unwrap();
    let credentials = dir.path().join("credentials");
    std::fs::write(
        &credentials,
        format!("[default]\naws_access_key_id = {ACCESS_KEY_ID}\naws_secret_access_key = x\n"),
    )
    .unwrap();
    let mut command = tokio::process::Command::new(env!("CARGO_BIN_EXE_tdf-iroh-s3"));
    command
        .env_clear()
        .env("HOME", dir.path())
        .env("AWS_CONFIG_FILE", dir.path().join("config"))
        .env("AWS_SHARED_CREDENTIALS_FILE", &credentials)
        .env("AWS_EC2_METADATA_DISABLED", "true")
        .arg("--config")
        .arg(&config)
        .args([
            "release-owner",
            "--hash",
            HASH,
            "--subject",
            "u1",
            "--reason",
            "test",
        ]);
    if let Some(filter) = rust_log {
        command.env("RUST_LOG", filter);
    }
    let out = command.output().await.unwrap();
    (
        out.status.success(),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

#[tokio::test(flavor = "multi_thread")]
async fn an_operator_commands_stdout_is_only_its_report() {
    let (ok, stdout, stderr) = release_owner(None).await;
    assert!(!ok, "nothing to release: exit 1");
    assert_eq!(
        stdout,
        format!("not released: {HASH} has no owner record\n"),
        "stderr: {stderr}"
    );
    assert!(stderr.contains("Config loaded"), "logs on stderr: {stderr}");
    assert!(
        !stderr.contains(ACCESS_KEY_ID),
        "no credential lines: {stderr}"
    );
}

/// `RUST_LOG` still decides, and asking for `aws_config` shows its lines,
/// on stderr too.
#[tokio::test(flavor = "multi_thread")]
async fn rust_log_still_decides_what_an_operator_command_logs() {
    let (_, stdout, stderr) = release_owner(Some("info")).await;
    assert_eq!(
        stdout,
        format!("not released: {HASH} has no owner record\n")
    );
    assert!(stderr.contains(ACCESS_KEY_ID), "{stderr}");
}
