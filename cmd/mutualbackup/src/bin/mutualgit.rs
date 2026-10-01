use std::ffi::OsString;
use std::io::{self, Write};
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
    /// Stage exact file or symlink bytes, or a tracked path's deletion.
    Add {
        /// Discard an unfinished add after its captured source changed.
        #[arg(long)]
        abort_pending: bool,
        #[arg(required = true)]
        paths: Vec<PathBuf>,
    },
    /// Remove paths from the staged index while keeping working files.
    Rm {
        /// Required until worktree-removing `rm` is implemented.
        #[arg(long)]
        cached: bool,
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
    /// List local branches or create one at the current commit.
    Branch { name: Option<String> },
    /// Switch to a branch using exact-byte reflink checkout.
    Switch { name: String },
    /// Check out a branch using the same protected worktree transition.
    Checkout { name: String },
    /// Push the current branch to an existing local bare Git repository.
    Push { destination: PathBuf },
    /// Fetch branches from an existing local bare Git repository.
    Fetch { source: PathBuf },
    /// Fetch and fast-forward the selected branch from a local bare repository.
    Pull { source: PathBuf },
    /// Show raw-byte changes in the worktree or staged index.
    Diff {
        #[arg(long, alias = "staged")]
        cached: bool,
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
        Command::Add {
            abort_pending,
            paths,
        } => {
            let (root, repository_id) = discover_repository(&working_directory)?;
            for path in paths {
                let relative = relative_for_add(&root, &working_directory, &path)?;
                if abort_pending {
                    let LocalResponse::GitPendingAddAbandoned { abandoned } = local_control_call(
                        &socket,
                        &LocalRequest::GitAbandonPendingAdd {
                            repository_id,
                            path: relative.clone(),
                        },
                    )
                    .await?
                    else {
                        bail!("daemon returned the wrong response to pending add abort");
                    };
                    println!(
                        "{} {}",
                        if abandoned {
                            "abandoned"
                        } else {
                            "no pending add for"
                        },
                        relative.display()
                    );
                    continue;
                }
                let response = local_control_call(
                    &socket,
                    &LocalRequest::GitAdd {
                        repository_id,
                        path: relative.clone(),
                    },
                )
                .await?;
                match response {
                    LocalResponse::GitFileStaged(staged)
                        if staged.repository_id == repository_id && staged.path == relative =>
                    {
                        println!("staged {} {} (local)", staged.oid, staged.path.display());
                    }
                    LocalResponse::GitDeletionStaged {
                        repository_id: returned_id,
                        path,
                    } if returned_id == repository_id && path == relative => {
                        println!("staged deletion of {} (local)", path.display());
                    }
                    _ => bail!("daemon returned the wrong response to Git add"),
                }
            }
        }
        Command::Rm { cached, paths } => {
            if !cached {
                bail!("only `rm --cached` is supported; worktree files were not removed");
            }
            let (root, repository_id) = discover_repository(&working_directory)?;
            for path in paths {
                let relative = relative_for_add(&root, &working_directory, &path)?;
                let LocalResponse::GitCachedPathRemoved { removed } = local_control_call(
                    &socket,
                    &LocalRequest::GitRemoveCached {
                        repository_id,
                        path: relative.clone(),
                    },
                )
                .await?
                else {
                    bail!("daemon returned the wrong response to Git index removal");
                };
                if !removed {
                    bail!("{} is not staged in the index", relative.display());
                }
                println!("removed {} from index", relative.display());
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
        Command::Branch { name } => {
            let (_, repository_id) = discover_repository(&working_directory)?;
            if let Some(name) = name {
                let LocalResponse::GitBranchCreated(branch) = local_control_call(
                    &socket,
                    &LocalRequest::GitCreateBranch {
                        repository_id,
                        name,
                    },
                )
                .await?
                else {
                    bail!("daemon returned the wrong response to Git branch creation");
                };
                if branch.repository_id != repository_id {
                    bail!("daemon created a branch in another repository");
                }
                println!(
                    "created branch {} at {}",
                    branch.name,
                    git2::Oid::from_bytes(&branch.oid)?
                );
            } else {
                let LocalResponse::GitBranches(branches) =
                    local_control_call(&socket, &LocalRequest::GitBranches { repository_id })
                        .await?
                else {
                    bail!("daemon returned the wrong response to Git branch listing");
                };
                for branch in branches {
                    if branch.repository_id != repository_id {
                        bail!("daemon listed a branch from another repository");
                    }
                    println!("{} {}", if branch.current { '*' } else { ' ' }, branch.name);
                }
            }
        }
        Command::Switch { name } | Command::Checkout { name } => {
            let (_, repository_id) = discover_repository(&working_directory)?;
            let LocalResponse::GitBranchSelected(branch) = local_control_call(
                &socket,
                &LocalRequest::GitSwitchBranch {
                    repository_id,
                    name,
                },
            )
            .await?
            else {
                bail!("daemon returned the wrong response to Git switch");
            };
            if branch.repository_id != repository_id || !branch.current {
                bail!("daemon selected a branch in another repository");
            }
            println!("Switched to branch '{}'", branch.name);
        }
        Command::Push { destination } => {
            let (_, repository_id) = discover_repository(&working_directory)?;
            let destination = working_directory
                .join(destination)
                .canonicalize()
                .context("cannot resolve bare Git destination")?;
            let LocalResponse::GitPushed {
                repository_id: returned_id,
                oid,
            } = local_control_call(
                &socket,
                &LocalRequest::GitPushBare {
                    repository_id,
                    path: destination.clone(),
                },
            )
            .await?
            else {
                bail!("daemon returned the wrong response to Git push");
            };
            if returned_id != repository_id {
                bail!("daemon pushed another repository");
            }
            println!(
                "Pushed {} to {}",
                git2::Oid::from_bytes(&oid)?,
                destination.display()
            );
        }
        Command::Fetch { source } => {
            let (_, repository_id) = discover_repository(&working_directory)?;
            let source = working_directory.join(source);
            let LocalResponse::GitFetched {
                repository_id: returned_id,
                branch_count,
            } = local_control_call(
                &socket,
                &LocalRequest::GitFetchBare {
                    repository_id,
                    path: source.clone(),
                },
            )
            .await?
            else {
                bail!("daemon returned the wrong response to Git fetch");
            };
            if returned_id != repository_id {
                bail!("daemon fetched another repository");
            }
            println!(
                "Fetched {branch_count} branch(es) from {}",
                source.display()
            );
        }
        Command::Pull { source } => {
            let (_, repository_id) = discover_repository(&working_directory)?;
            let source = working_directory.join(source);
            let LocalResponse::GitPulled {
                repository_id: returned_id,
                oid,
            } = local_control_call(
                &socket,
                &LocalRequest::GitPullBare {
                    repository_id,
                    path: source.clone(),
                },
            )
            .await?
            else {
                bail!("daemon returned the wrong response to Git pull");
            };
            if returned_id != repository_id {
                bail!("daemon pulled another repository");
            }
            println!(
                "Pulled {} from {}",
                git2::Oid::from_bytes(&oid)?,
                source.display()
            );
        }
        Command::Diff { cached } => {
            let (_, repository_id) = discover_repository(&working_directory)?;
            let LocalResponse::GitDiff(diff) = local_control_call(
                &socket,
                &LocalRequest::GitDiff {
                    repository_id,
                    cached,
                },
            )
            .await?
            else {
                bail!("daemon returned the wrong response to Git diff");
            };
            if diff.repository_id != repository_id || diff.cached != cached {
                bail!("daemon returned a diff for another repository or comparison");
            }
            io::stdout().write_all(&diff.patch)?;
        }
        Command::Status => {
            let (_, repository_id) = discover_repository(&working_directory)?;
            let LocalResponse::GitStatus(status) =
                local_control_call(&socket, &LocalRequest::GitStatus { repository_id }).await?
            else {
                bail!("daemon returned the wrong response to Git status");
            };
            println!("On branch {}", status.branch);
            if status.head_oid.is_some() {
                if status.history_backed_up {
                    println!("Local history is protected by a signed backup");
                } else {
                    println!("Local commits are awaiting a signed backup");
                }
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
