#![cfg(target_os = "linux")]

use std::fs;
use std::io::{Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::fs::symlink;
use std::os::unix::net::UnixListener;
use std::path::PathBuf;
use std::process::Command;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use mb_git::{FetchError, GitRepository, RepositoryError};
use mb_node::{GitRepositoryInfo, LocalRequest, LocalResponse, WireError};
use uuid::Uuid;

#[path = "support/binaries.rs"]
mod binaries;
use binaries::program;

#[test]
#[ignore = "requires an explicitly provisioned Btrfs test filesystem"]
fn stock_git_fetches_and_pushes_through_native_anchors() {
    // Control sockets must stay short even when the provisioned source area
    // has a long path. Keep IPC in its own private temporary directory.
    let control_directory = tempfile::Builder::new()
        .prefix("mb-git-ctl-")
        .permissions(fs::Permissions::from_mode(0o700))
        .tempdir()
        .unwrap();
    let socket = control_directory.path().join("socket");
    let listener = UnixListener::bind(&socket).unwrap();
    listener.set_nonblocking(true).unwrap();
    let test_root = PathBuf::from(
        std::env::var_os("MUTUALBACKUP_REFLINK_TEST_ROOT")
            .expect("the reflink acceptance harness must set MUTUALBACKUP_REFLINK_TEST_ROOT"),
    );
    let run_root = test_root.join(format!("git-remote-helper-{}", Uuid::new_v4()));
    let source_root = run_root.join("source");
    let stock_root = run_root.join("stock");
    let hidden_root = run_root.join("guarded-view");
    fs::create_dir_all(&source_root).unwrap();
    fs::create_dir_all(&stock_root).unwrap();
    fs::create_dir_all(&hidden_root).unwrap();
    let payload = b"exact\r\nbytes\0\xff\n";
    fs::write(source_root.join("tracked"), payload).unwrap();
    let repository_id = Uuid::new_v4();
    let key = [91_u8; 32];
    let repository = GitRepository::init(&source_root, repository_id, &key).unwrap();
    let staged = repository.stage_file("tracked").unwrap();
    let commit = repository
        .commit("Author", "a@example.test", "stock Git fetch")
        .unwrap();
    let lightweight_tag = repository.create_tag("lightweight", None).unwrap();
    let annotated_tag = repository
        .create_annotated_tag(
            "annotated",
            None,
            "Tagger",
            "tagger@example.test",
            "release notes\r\n",
        )
        .unwrap();
    drop(repository);
    let output = Command::new("git")
        .args(["init", "-q"])
        .arg(&stock_root)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stop = Arc::new(AtomicBool::new(false));
    let server_stop = stop.clone();
    let server_root = source_root.clone();
    let server_hidden_root = hidden_root.clone();
    let server = std::thread::spawn(move || {
        let repository = GitRepository::open(&server_root, repository_id, &key).unwrap();
        while !server_stop.load(Ordering::Relaxed) {
            let (mut stream, _) = match listener.accept() {
                Ok(connection) => connection,
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    std::thread::sleep(Duration::from_millis(5));
                    continue;
                }
                Err(error) => panic!("local test socket failed: {error}"),
            };
            let mut length = [0_u8; 4];
            stream.read_exact(&mut length).unwrap();
            let mut request = vec![0_u8; u32::from_be_bytes(length) as usize];
            stream.read_exact(&mut request).unwrap();
            let envelope: serde_json::Value = serde_json::from_slice(&request).unwrap();
            let request_id = envelope["request_id"].clone();
            let request: LocalRequest =
                serde_json::from_value(envelope["request"].clone()).unwrap();
            let response: Result<LocalResponse, WireError> = match request {
                LocalRequest::GitLocate { path } => {
                    assert_eq!(path, server_hidden_root);
                    Ok(LocalResponse::GitLocated(Some(GitRepositoryInfo {
                        format_version: 1,
                        repository_id,
                        path: server_hidden_root.clone(),
                    })))
                }
                LocalRequest::GitBranches {
                    repository_id: requested,
                } => {
                    assert_eq!(requested, repository_id);
                    Ok(LocalResponse::GitBranches(repository.branches().unwrap()))
                }
                LocalRequest::GitStatus {
                    repository_id: requested,
                } => {
                    assert_eq!(requested, repository_id);
                    Ok(LocalResponse::GitStatus(repository.status().unwrap()))
                }
                LocalRequest::GitTags {
                    repository_id: requested,
                } => {
                    assert_eq!(requested, repository_id);
                    Ok(LocalResponse::GitTags(repository.tags().unwrap()))
                }
                LocalRequest::GitExportToGitRepository {
                    repository_id: requested,
                    source_root,
                    destination,
                    advertised,
                } => {
                    assert_eq!(requested, repository_id);
                    assert_eq!(source_root, server_root);
                    let object_count = repository
                        .export_to_git_repository(&destination, &advertised)
                        .unwrap();
                    Ok(LocalResponse::GitObjectsExported {
                        repository_id,
                        object_count,
                    })
                }
                LocalRequest::GitExportToGitRepositoryV2 {
                    repository_id: requested,
                    source_root,
                    destination,
                    advertised_branches,
                    advertised_tags,
                } => {
                    assert_eq!(requested, repository_id);
                    assert!(source_root == server_root || source_root == server_hidden_root);
                    let object_count = repository
                        .export_to_git_repository_with_tags(
                            &destination,
                            &advertised_branches,
                            &advertised_tags,
                        )
                        .unwrap();
                    Ok(LocalResponse::GitObjectsExported {
                        repository_id,
                        object_count,
                    })
                }
                LocalRequest::GitReceivePushedBranch {
                    repository_id: requested,
                    source_root,
                    source_git_directory,
                    target_branch,
                    target_oid,
                    expected_old,
                } => {
                    assert_eq!(requested, repository_id);
                    assert_eq!(source_root, server_root);
                    repository
                        .receive_pushed_branch(
                            &source_git_directory,
                            &target_branch,
                            target_oid,
                            expected_old,
                        )
                        .map(|()| LocalResponse::GitPushReceived {
                            repository_id,
                            branch: target_branch,
                            oid: target_oid,
                        })
                        .map_err(WireError::operation)
                }
                LocalRequest::GitReceivePushedTag {
                    repository_id: requested,
                    source_root,
                    source_git_directory,
                    target_tag,
                    target_oid,
                    expected_old,
                } => {
                    assert_eq!(requested, repository_id);
                    assert_eq!(source_root, server_root);
                    repository
                        .receive_pushed_tag(
                            &source_git_directory,
                            &target_tag,
                            target_oid,
                            expected_old,
                        )
                        .map(|()| LocalResponse::GitTagPushReceived {
                            repository_id,
                            name: target_tag,
                            oid: target_oid,
                        })
                        .map_err(WireError::operation)
                }
                _ => panic!("unexpected Git helper request"),
            };
            let response = serde_json::json!({
                "format_version": 2,
                "request_id": request_id,
                "result": response,
            });
            let bytes = serde_json::to_vec(&response).unwrap();
            stream
                .write_all(&(bytes.len() as u32).to_be_bytes())
                .unwrap();
            stream.write_all(&bytes).unwrap();
        }
    });

    let helper = PathBuf::from(program("git-remote-mutualbackup"));
    let git_alias = run_root.join("git");
    symlink(program("mutualgit"), &git_alias).unwrap();
    let output = Command::new(&git_alias)
        .arg("-C")
        .arg(&source_root)
        .arg("--socket")
        .arg(&socket)
        .arg("branch")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(String::from_utf8_lossy(&output.stdout).contains("main"));
    let attributes = run_root.join("global-attributes");
    fs::write(&attributes, b"tracked text eol=lf filter=probe\n").unwrap();
    let marker = run_root.join("filter-ran");
    let config = run_root.join("conversion-config");
    fs::write(
        &config,
        format!(
            "[core]\n\tautocrlf = true\n\tattributesFile = {}\n[filter \"probe\"]\n\tclean = sh -c 'touch \"$MUTUALBACKUP_FILTER_MARKER\"; cat'\n",
            attributes.display()
        ),
    )
    .unwrap();
    let status = |expected_dirty: bool| {
        let output = Command::new(&git_alias)
            .arg("-C")
            .arg(&source_root)
            .arg("--socket")
            .arg(&socket)
            .arg("status")
            .env("GIT_CONFIG_GLOBAL", &config)
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("MUTUALBACKUP_FILTER_MARKER", &marker)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let stdout = String::from_utf8(output.stdout).unwrap();
        assert!(stdout.contains("Content conversion: disabled (raw file bytes)"));
        assert_eq!(stdout.contains(" M tracked"), expected_dirty, "{stdout}");
        assert!(!marker.exists(), "the inherited clean filter ran");
    };
    status(false);
    fs::write(source_root.join("tracked"), b"exact\nbytes\0\xff\n").unwrap();
    status(true);
    fs::write(source_root.join("tracked"), payload).unwrap();
    let path = format!(
        "{}:{}",
        helper.parent().unwrap().display(),
        std::env::var("PATH").unwrap_or_default()
    );
    let output = Command::new("git")
        .arg("-C")
        .arg(&stock_root)
        .args(["fetch", "--no-tags"])
        .arg(format!("mutualbackup::{}", source_root.display()))
        .arg("refs/heads/main:refs/remotes/mb/main")
        .env("PATH", &path)
        .env("MUTUALBACKUP_CONTROL_SOCKET", &socket)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let output = Command::new("git")
        .arg("-C")
        .arg(&stock_root)
        .args([
            "cat-file",
            "blob",
            &git2::Oid::from_bytes(&staged.oid).unwrap().to_string(),
        ])
        .output()
        .unwrap();
    assert!(output.status.success());
    assert_eq!(output.stdout, payload);
    let output = Command::new("git")
        .arg("-C")
        .arg(&stock_root)
        .args(["rev-parse", "refs/remotes/mb/main"])
        .output()
        .unwrap();
    assert!(output.status.success());
    assert_eq!(
        String::from_utf8(output.stdout).unwrap().trim(),
        git2::Oid::from_bytes(&commit.oid).unwrap().to_string()
    );
    let hidden_stock = run_root.join("hidden-stock");
    let output = Command::new("git")
        .args(["init", "-q"])
        .arg(&hidden_stock)
        .output()
        .unwrap();
    assert!(output.status.success());
    let output = Command::new("git")
        .arg("-C")
        .arg(&hidden_stock)
        .args(["fetch", "--no-tags"])
        .arg(format!("mutualbackup::{}", hidden_root.display()))
        .arg("refs/heads/main:refs/remotes/guarded/main")
        .env("PATH", &path)
        .env("MUTUALBACKUP_CONTROL_SOCKET", &socket)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let output = Command::new("git")
        .arg("-C")
        .arg(&hidden_stock)
        .args([
            "cat-file",
            "blob",
            &git2::Oid::from_bytes(&staged.oid).unwrap().to_string(),
        ])
        .output()
        .unwrap();
    assert!(output.status.success());
    assert_eq!(output.stdout, payload);
    for tag in [&lightweight_tag, &annotated_tag] {
        let reference = format!("refs/tags/{}", tag.name);
        let output = Command::new("git")
            .arg("-C")
            .arg(&stock_root)
            .args(["fetch", "--no-tags"])
            .arg(format!("mutualbackup::{}", source_root.display()))
            .arg(format!("{reference}:{reference}"))
            .env("PATH", &path)
            .env("MUTUALBACKUP_CONTROL_SOCKET", &socket)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let stock = git2::Repository::open(&stock_root).unwrap();
        assert_eq!(
            stock
                .find_reference(&reference)
                .unwrap()
                .target()
                .unwrap()
                .as_bytes(),
            tag.oid
        );
    }
    let stock = git2::Repository::open(&stock_root).unwrap();
    assert_eq!(
        stock
            .find_tag(git2::Oid::from_bytes(&annotated_tag.oid).unwrap())
            .unwrap()
            .target_id()
            .as_bytes(),
        commit.oid
    );

    let clone_root = run_root.join("clone");
    let output = Command::new("git")
        .args(["-c", "core.autocrlf=false", "clone", "--no-tags"])
        .arg(format!("mutualbackup::{}", source_root.display()))
        .arg(&clone_root)
        .env("PATH", &path)
        .env("MUTUALBACKUP_CONTROL_SOCKET", &socket)
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(fs::read(clone_root.join("tracked")).unwrap(), payload);

    let output = Command::new("git")
        .arg("-C")
        .arg(&clone_root)
        .args(["checkout", "-q", "-b", "topic"])
        .output()
        .unwrap();
    assert!(output.status.success());
    let pushed_bytes = b"pushed\r\nraw\0bytes\xff";
    fs::write(clone_root.join("tracked"), pushed_bytes).unwrap();
    let output = Command::new("git")
        .arg("-C")
        .arg(&clone_root)
        .args(["-c", "core.autocrlf=false", "add", "tracked"])
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .output()
        .unwrap();
    assert!(output.status.success());
    let output = Command::new("git")
        .arg("-C")
        .arg(&clone_root)
        .args([
            "-c",
            "user.name=Stock",
            "-c",
            "user.email=stock@example.test",
            "commit",
            "-qm",
            "pushed branch",
        ])
        .output()
        .unwrap();
    assert!(output.status.success());
    let output = Command::new("git")
        .arg("-C")
        .arg(&clone_root)
        .args(["rev-parse", "HEAD"])
        .output()
        .unwrap();
    assert!(output.status.success());
    let pushed_oid = String::from_utf8(output.stdout).unwrap().trim().to_owned();
    let output = Command::new("git")
        .arg("-C")
        .arg(&clone_root)
        .args(["push"])
        .arg(format!("mutualbackup::{}", source_root.display()))
        .arg("refs/heads/topic:refs/heads/topic")
        .env("PATH", &path)
        .env("MUTUALBACKUP_CONTROL_SOCKET", &socket)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let pushed_again = b"second push\nwith\0raw\r\n";
    fs::write(clone_root.join("tracked"), pushed_again).unwrap();
    let output = Command::new("git")
        .arg("-C")
        .arg(&clone_root)
        .args(["-c", "core.autocrlf=false", "add", "tracked"])
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .output()
        .unwrap();
    assert!(output.status.success());
    let output = Command::new("git")
        .arg("-C")
        .arg(&clone_root)
        .args([
            "-c",
            "user.name=Stock",
            "-c",
            "user.email=stock@example.test",
            "commit",
            "-qm",
            "fast forward topic",
        ])
        .output()
        .unwrap();
    assert!(output.status.success());
    let output = Command::new("git")
        .arg("-C")
        .arg(&clone_root)
        .args(["rev-parse", "HEAD"])
        .output()
        .unwrap();
    assert!(output.status.success());
    let fast_forward_oid = String::from_utf8(output.stdout).unwrap().trim().to_owned();
    assert_ne!(pushed_oid, fast_forward_oid);
    let output = Command::new("git")
        .arg("-C")
        .arg(&clone_root)
        .args(["push"])
        .arg(format!("mutualbackup::{}", source_root.display()))
        .arg("refs/heads/topic:refs/heads/topic")
        .env("PATH", &path)
        .env("MUTUALBACKUP_CONTROL_SOCKET", &socket)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let output = Command::new("git")
        .arg("-C")
        .arg(&clone_root)
        .args([
            "-c",
            "user.name=Stock",
            "-c",
            "user.email=stock@example.test",
            "tag",
            "-a",
            "-m",
            "stock release\r\n",
            "stock-release",
        ])
        .output()
        .unwrap();
    assert!(output.status.success());
    let stock_tag = git2::Repository::open(&clone_root)
        .unwrap()
        .find_reference("refs/tags/stock-release")
        .unwrap()
        .target()
        .unwrap();
    let output = Command::new("git")
        .arg("-C")
        .arg(&clone_root)
        .args(["push"])
        .arg(format!("mutualbackup::{}", source_root.display()))
        .arg("refs/tags/stock-release:refs/tags/stock-release")
        .env("PATH", &path)
        .env("MUTUALBACKUP_CONTROL_SOCKET", &socket)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let output = Command::new("git")
        .arg("-C")
        .arg(&clone_root)
        .args(["tag", "stock-light"])
        .output()
        .unwrap();
    assert!(output.status.success());
    let output = Command::new("git")
        .arg("-C")
        .arg(&clone_root)
        .args(["push"])
        .arg(format!("mutualbackup::{}", source_root.display()))
        .arg("refs/tags/stock-light:refs/tags/stock-light")
        .env("PATH", &path)
        .env("MUTUALBACKUP_CONTROL_SOCKET", &socket)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let roundtrip_root = run_root.join("roundtrip");
    let output = Command::new("git")
        .args(["-c", "core.autocrlf=false", "clone", "--no-tags"])
        .arg(format!("mutualbackup::{}", source_root.display()))
        .arg(&roundtrip_root)
        .env("PATH", &path)
        .env("MUTUALBACKUP_CONTROL_SOCKET", &socket)
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let output = Command::new("git")
        .arg("-C")
        .arg(&roundtrip_root)
        .args(["checkout", "-q", "topic"])
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        fs::read(roundtrip_root.join("tracked")).unwrap(),
        pushed_again
    );
    let output = Command::new("git")
        .arg("-C")
        .arg(&roundtrip_root)
        .args(["fetch", "--no-tags"])
        .arg(format!("mutualbackup::{}", source_root.display()))
        .arg("refs/tags/stock-release:refs/tags/stock-release")
        .env("PATH", &path)
        .env("MUTUALBACKUP_CONTROL_SOCKET", &socket)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        git2::Repository::open(&roundtrip_root)
            .unwrap()
            .find_reference("refs/tags/stock-release")
            .unwrap()
            .target()
            .unwrap(),
        stock_tag
    );
    let output = Command::new("git")
        .arg("-C")
        .arg(&clone_root)
        .args(["push"])
        .arg(format!("mutualbackup::{}", source_root.display()))
        .arg("refs/heads/topic:refs/heads/main")
        .env("PATH", &path)
        .env("MUTUALBACKUP_CONTROL_SOCKET", &socket)
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("selected by a worktree"),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    stop.store(true, Ordering::Relaxed);
    server.join().unwrap();

    let repository = GitRepository::open(&source_root, repository_id, &key).unwrap();
    assert_eq!(fs::read(source_root.join("tracked")).unwrap(), payload);
    assert_eq!(
        repository
            .branches()
            .unwrap()
            .into_iter()
            .find(|branch| branch.name == "main")
            .unwrap()
            .oid,
        commit.oid
    );
    assert_eq!(
        git2::Oid::from_bytes(
            &repository
                .branches()
                .unwrap()
                .into_iter()
                .find(|branch| branch.name == "topic")
                .unwrap()
                .oid
        )
        .unwrap()
        .to_string(),
        fast_forward_oid
    );
    assert_eq!(
        repository
            .tags()
            .unwrap()
            .into_iter()
            .find(|tag| tag.name == "stock-release")
            .unwrap()
            .oid,
        stock_tag.as_bytes()
    );
    let stock = git2::Repository::open(&clone_root).unwrap();
    let topic_object = stock
        .find_object(git2::Oid::from_str(&fast_forward_oid).unwrap(), None)
        .unwrap();
    let signature = git2::Signature::now("Stock", "stock@example.test").unwrap();
    let changed_tag = stock
        .tag_annotation_create("stock-release", &topic_object, &signature, "changed")
        .unwrap();
    assert!(matches!(
        repository.receive_pushed_tag(
            stock.path(),
            "stock-release",
            changed_tag.as_bytes().try_into().unwrap(),
            Some(stock_tag.as_bytes().try_into().unwrap()),
        ),
        Err(RepositoryError::Fetch(FetchError::TagExists))
    ));
    assert!(matches!(
        repository.receive_pushed_tag(
            stock.path(),
            "stock-release/nested",
            changed_tag.as_bytes().try_into().unwrap(),
            None,
        ),
        Err(RepositoryError::Fetch(FetchError::TagExists))
    ));
    let main_oid = commit.oid;
    let topic_oid = git2::Oid::from_str(&fast_forward_oid).unwrap();
    assert!(matches!(
        repository.receive_pushed_branch(
            clone_root.join(".git"),
            "main",
            topic_oid.as_bytes().try_into().unwrap(),
            Some(main_oid),
        ),
        Err(RepositoryError::Fetch(FetchError::CheckedOutBranch))
    ));
    assert!(matches!(
        repository.receive_pushed_branch(
            clone_root.join(".git"),
            "topic",
            main_oid,
            Some(topic_oid.as_bytes().try_into().unwrap()),
        ),
        Err(RepositoryError::Fetch(FetchError::NonFastForward))
    ));
    assert_eq!(
        repository
            .branches()
            .unwrap()
            .into_iter()
            .find(|branch| branch.name == "topic")
            .unwrap()
            .oid,
        topic_oid.as_bytes()
    );
    repository.switch_branch("topic").unwrap();
    assert_eq!(fs::read(source_root.join("tracked")).unwrap(), pushed_again);
    let graph = repository.export_graph_source().unwrap();
    drop(repository);
    for blob in graph.blobs {
        blob.anchor.remove().unwrap();
    }
    fs::remove_dir_all(run_root).unwrap();
}
