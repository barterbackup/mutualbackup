use std::ffi::OsString;
use std::path::{Component, Path, PathBuf};

use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand};
use mb_git::GitChange;
use mb_node::{LocalRequest, LocalResponse, local_control_call};
use mb_store::git_catalog_marker;
use mutualbackup::default_control_socket;
use uuid::Uuid;

#[derive(Debug, Parser)]
#[command(
    name = "mutualgit",
    version,
    about = "Git-compatible MutualBackup history"
)]
struct Cli {
    /// Run as if started in this directory.
    #[arg(short = 'C', global = true)]
    directory: Option<PathBuf>,
    /// Local mutualbackupd control socket.
    #[arg(long, global = true)]
    socket: Option<PathBuf>,
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Enroll this directory as a protected Git-compatible repository.
    Init { directory: Option<PathBuf> },
    /// Stage exact regular-file bytes in native reflink anchors.
    Add {
        #[arg(required = true)]
        paths: Vec<PathBuf>,
    },
    /// Commit the staged snapshot to the current local branch.
    Commit {
        #[arg(short = 'm', long)]
        message: String,
        #[arg(long)]
        author_name: Option<String>,
        #[arg(long)]
        author_email: Option<String>,
    },
    /// Show commits reachable from the current local branch.
    Log {
        #[arg(short = 'n', long = "max-count", default_value_t = 10)]
        limit: u32,
    },
    /// Show staged, working-tree, and backup-protection state.
    Status,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    let working_directory = cli
        .directory
        .unwrap_or(std::env::current_dir()?)
        .canonicalize()
        .context("cannot resolve working directory")?;
    let socket = cli.socket.unwrap_or_else(default_control_socket);
    match cli.command {
        Command::Init { directory } => {
            let root = directory
                .map(|path| working_directory.join(path))
                .unwrap_or(working_directory);
            let LocalResponse::GitRepositoryInitialized(info) =
                local_control_call(&socket, &LocalRequest::GitInit { path: root }).await?
            else {
                bail!("daemon returned the wrong response to Git initialization");
            };
            println!(
                "Initialized MutualBackup Git repository {} in {}",
                info.repository_id,
                info.path.display()
            );
        }
        Command::Add { paths } => {
            let (root, repository_id) = discover_repository(&working_directory)?;
            for path in paths {
                let relative = relative_for_add(&root, &working_directory, &path)?;
                let LocalResponse::GitFileStaged(staged) = local_control_call(
                    &socket,
                    &LocalRequest::GitAdd {
                        repository_id,
                        path: relative,
                    },
                )
                .await?
                else {
                    bail!("daemon returned the wrong response to Git add");
                };
                if staged.repository_id != repository_id {
                    bail!("daemon staged a file for another repository");
                }
                println!("staged {} {} (local)", staged.oid, staged.path.display());
            }
        }
        Command::Commit {
            message,
            author_name,
            author_email,
        } => {
            let (_, repository_id) = discover_repository(&working_directory)?;
            let author_name = author_name
                .map(Ok)
                .unwrap_or_else(|| author_field("GIT_AUTHOR_NAME", "user.name"))?;
            let author_email = author_email
                .map(Ok)
                .unwrap_or_else(|| author_field("GIT_AUTHOR_EMAIL", "user.email"))?;
            let LocalResponse::GitCommitted(commit) = local_control_call(
                &socket,
                &LocalRequest::GitCommit {
                    repository_id,
                    author_name,
                    author_email,
                    message,
                },
            )
            .await?
            else {
                bail!("daemon returned the wrong response to Git commit");
            };
            if commit.repository_id != repository_id {
                bail!("daemon committed another repository");
            }
            println!(
                "[{} {}] committed locally; backup pending",
                commit.branch,
                git2::Oid::from_bytes(&commit.oid)?
            );
        }
        Command::Log { limit } => {
            let (_, repository_id) = discover_repository(&working_directory)?;
            let LocalResponse::GitLog(commits) = local_control_call(
                &socket,
                &LocalRequest::GitLog {
                    repository_id,
                    limit,
                },
            )
            .await?
            else {
                bail!("daemon returned the wrong response to Git log");
            };
            for commit in commits {
                println!("commit {}", git2::Oid::from_bytes(&commit.oid)?);
                println!(
                    "Author: {} <{}>",
                    String::from_utf8_lossy(&commit.author_name),
                    String::from_utf8_lossy(&commit.author_email)
                );
                println!();
                for line in String::from_utf8_lossy(&commit.message).lines() {
                    println!("    {line}");
                }
                println!();
            }
        }
        Command::Status => {
            let (_, repository_id) = discover_repository(&working_directory)?;
            let LocalResponse::GitStatus(status) =
                local_control_call(&socket, &LocalRequest::GitStatus { repository_id }).await?
            else {
                bail!("daemon returned the wrong response to Git status");
            };
            println!("On branch {}", status.branch);
            if !status.history_backed_up && status.head_oid.is_some() {
                println!("Local commits are awaiting a signed backup");
            }
            for change in status.changes {
                println!(
                    "{}{} {}",
                    change_code(change.staged),
                    change_code(change.worktree),
                    display_path(&change.path)
                );
            }
            for path in status.untracked {
                println!("?? {}", display_path(&path));
            }
            for path in status.pending_adds {
                println!("pending add {}", display_path(&path));
            }
        }
    }
    Ok(())
}

fn display_path(bytes: &[u8]) -> String {
    bytes
        .iter()
        .flat_map(|byte| std::ascii::escape_default(*byte))
        .map(char::from)
        .collect()
}

fn change_code(change: Option<GitChange>) -> char {
    match change {
        Some(GitChange::Added) => 'A',
        Some(GitChange::Modified) => 'M',
        Some(GitChange::Deleted) => 'D',
        Some(GitChange::TypeChanged) => 'T',
        None => ' ',
    }
}

fn author_field(environment: &str, config_key: &str) -> Result<String> {
    if let Some(value) = std::env::var_os(environment) {
        return value
            .into_string()
            .map_err(|_| anyhow::anyhow!("{environment} is not valid UTF-8"));
    }
    git2::Config::open_default()?
        .get_string(config_key)
        .with_context(|| format!("set {environment} or Git {config_key} before committing"))
}

fn discover_repository(start: &Path) -> Result<(PathBuf, Uuid)> {
    for directory in start.ancestors() {
        if let Some(repository_id) = git_catalog_marker(directory)? {
            return Ok((directory.to_path_buf(), repository_id));
        }
    }
    bail!("no initialized MutualBackup Git repository contains this directory")
}

fn relative_for_add(root: &Path, working_directory: &Path, path: &Path) -> Result<PathBuf> {
    let candidate = if path.is_absolute() {
        path.strip_prefix(root)
            .context("file is outside the repository")?
            .to_path_buf()
    } else {
        working_directory
            .strip_prefix(root)
            .context("working directory is outside the repository")?
            .join(path)
    };
    let mut parts = Vec::<OsString>::new();
    for component in candidate.components() {
        match component {
            Component::Normal(name) => parts.push(name.to_os_string()),
            Component::CurDir => {}
            Component::ParentDir => {
                if parts.pop().is_none() {
                    bail!("file is outside the repository");
                }
            }
            Component::RootDir | Component::Prefix(_) => bail!("invalid repository path"),
        }
    }
    if parts.is_empty() {
        bail!("add requires a file path");
    }
    Ok(parts.iter().collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn add_paths_stay_inside_the_marked_repository() {
        let root = Path::new("/project");
        let subdir = Path::new("/project/src");
        assert_eq!(
            relative_for_add(root, subdir, Path::new("../README.md")).unwrap(),
            Path::new("README.md")
        );
        assert_eq!(
            relative_for_add(root, subdir, Path::new("./main.rs")).unwrap(),
            Path::new("src/main.rs")
        );
        assert!(relative_for_add(root, subdir, Path::new("../../escape")).is_err());
        assert!(relative_for_add(root, subdir, Path::new("/outside")).is_err());
        assert_eq!(display_path(b"bad\xff\nname"), "bad\\xff\\nname");
    }
}
