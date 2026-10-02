use std::ffi::OsString;
use std::io::{self, Write};
use std::path::{Component, Path, PathBuf};

use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand};
use mb_git::{GitChange, linked_worktree_marker};
use mb_node::{LocalRequest, LocalResponse, local_control_call};
use mb_store::git_catalog_marker;
use mutualbackup::default_control_socket;
use uuid::Uuid;

#[derive(Debug, Parser)]
#[command(
    name = "mutualgit",
    version,
    about = "Git-compatible MutualBackup history",
    long_about = "Git-compatible MutualBackup history over native anchors. File bytes are preserved exactly: automatic line-ending conversion, clean/smudge filters, ident expansion, and working-tree encoding conversion are disabled, regardless of Git config or attributes."
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
    /// Create, list, resume, remove, or prune linked worktrees of this repository.
    Worktree {
        #[command(subcommand)]
        command: WorktreeCommand,
    },
    /// Stage exact file or symlink bytes, or a tracked path's deletion.
    Add {
        /// Discard an unfinished add after its captured source changed.
        #[arg(long)]
        abort_pending: bool,
        #[arg(required = true)]
        paths: Vec<PathBuf>,
    },
    /// Remove tracked paths from the index and working tree, or index only.
    Rm {
        /// Keep working files while removing the index entries.
        #[arg(long)]
        cached: bool,
        #[arg(required = true)]
        paths: Vec<PathBuf>,
    },
    /// Reset index paths, or reset both the index and tracked working files.
    Reset {
        #[arg(long)]
        hard: bool,
        paths: Vec<PathBuf>,
    },
    /// Restore selected paths from the index, HEAD, or both.
    Restore {
        #[arg(long)]
        staged: bool,
        #[arg(long)]
        worktree: bool,
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
    /// List, create, or delete local branches.
    Branch {
        /// Include fetched remote-tracking branches in the listing.
        #[arg(short = 'a', long)]
        all: bool,
        /// Delete a branch only if its tip is merged into the selected branch.
        #[arg(short = 'd', long = "delete", conflicts_with = "force_delete")]
        delete: bool,
        /// Delete an unmerged branch; protected history still follows retention policy.
        #[arg(short = 'D', long = "force-delete")]
        force_delete: bool,
        name: Option<String>,
        start_point: Option<String>,
    },
    /// List, create, or delete lightweight and annotated commit tags.
    Tag {
        #[arg(short = 'd', long = "delete")]
        delete: bool,
        #[arg(short = 'a', long = "annotate", conflicts_with = "delete")]
        annotate: bool,
        #[arg(short = 'm', long = "message", requires = "annotate")]
        message: Option<String>,
        name: Option<String>,
        start_point: Option<String>,
    },
    /// Keep a commit and its ancestors reachable from signed history backups.
    Pin { oid: String },
    /// Release an explicit commit pin; other refs and retained backups still apply.
    Unpin { oid: String },
    /// List explicitly pinned commit IDs.
    Pins,
    /// Delete unreachable Git metadata and native anchors after retention checks.
    #[command(visible_alias = "gc")]
    Prune,
    /// Switch to a branch using exact-byte reflink checkout.
    Switch { name: String },
    /// Check out a branch using the same protected worktree transition.
    Checkout { name: String },
    /// Push the current branch, a named branch, or a tag to a local bare Git repository.
    Push {
        destination: PathBuf,
        /// Optional BRANCH[:BRANCH], refs/heads/SRC:refs/heads/DST, or refs/tags/NAME.
        refspec: Option<String>,
    },
    /// Fetch branches and tags from an existing local Git repository.
    Fetch { source: PathBuf },
    /// Fetch and merge the selected branch from a local Git repository.
    Pull {
        source: PathBuf,
        #[arg(long)]
        author_name: Option<String>,
        #[arg(long)]
        author_email: Option<String>,
    },
    /// Merge a local branch, continue a resolved merge, or abort its session.
    Merge {
        branch: Option<String>,
        #[arg(long, conflicts_with_all = ["abort", "branch"])]
        continue_merge: bool,
        #[arg(long, conflicts_with_all = ["continue_merge", "branch"])]
        abort: bool,
        #[arg(long)]
        author_name: Option<String>,
        #[arg(long)]
        author_email: Option<String>,
    },
    /// Show raw-byte changes in the worktree or staged index.
    Diff {
        #[arg(long, alias = "staged")]
        cached: bool,
    },
    /// Show staged, working-tree, backup-protection, and raw-byte policy state.
    Status,
}

#[derive(Debug, Subcommand)]
enum WorktreeCommand {
    /// Check out a branch into an existing empty directory on the same filesystem.
    Add { path: PathBuf, branch: String },
    /// List the registered linked worktrees, including interrupted additions.
    List,
    /// Finish an interrupted linked-worktree checkout.
    Resume { worktree_id: Uuid },
    /// Remove a clean linked worktree and release its branch ownership.
    Remove { worktree_id: Uuid },
    /// Forget the registration of a clean linked worktree whose directory was removed.
    Prune {
        worktree_id: Uuid,
        /// Discard staged index changes after the worktree directory was removed.
        #[arg(long)]
        force: bool,
    },
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
    let pin_action = matches!(&cli.command, Command::Pin { .. });
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
        Command::Worktree { command } => {
            let repository_id = discover_shared_repository(&working_directory)?;
            match command {
                WorktreeCommand::Add { path, branch } => {
                    let destination = working_directory.join(path);
                    let LocalResponse::GitWorktreeRegistered(info) = local_control_call(
                        &socket,
                        &LocalRequest::GitWorktreeAdd {
                            repository_id,
                            path: destination,
                            branch,
                        },
                    )
                    .await?
                    else {
                        bail!("daemon returned the wrong response to worktree add");
                    };
                    if info.repository_id != repository_id {
                        bail!("daemon registered a worktree in another repository");
                    }
                    println!(
                        "Added worktree {} at {}",
                        info.worktree_id,
                        info.path.display()
                    );
                }
                WorktreeCommand::List => {
                    let LocalResponse::GitWorktrees(worktrees) =
                        local_control_call(&socket, &LocalRequest::GitWorktrees { repository_id })
                            .await?
                    else {
                        bail!("daemon returned the wrong response to worktree list");
                    };
                    for info in worktrees {
                        if info.repository_id != repository_id {
                            bail!("daemon listed a worktree in another repository");
                        }
                        println!(
                            "{} {} {} {:?}",
                            info.worktree_id,
                            info.path.display(),
                            info.target_branch,
                            info.state
                        );
                    }
                }
                WorktreeCommand::Resume { worktree_id } => {
                    let LocalResponse::GitWorktreeRegistered(info) = local_control_call(
                        &socket,
                        &LocalRequest::GitWorktreeResume {
                            repository_id,
                            worktree_id,
                        },
                    )
                    .await?
                    else {
                        bail!("daemon returned the wrong response to worktree resume");
                    };
                    if info.repository_id != repository_id || info.worktree_id != worktree_id {
                        bail!("daemon resumed another worktree");
                    }
                    println!(
                        "Worktree {} {:?} at {}",
                        worktree_id,
                        info.state,
                        info.path.display()
                    );
                }
                WorktreeCommand::Prune { worktree_id, force } => {
                    let LocalResponse::GitWorktreePruned(info) = local_control_call(
                        &socket,
                        &LocalRequest::GitWorktreePrune {
                            repository_id,
                            worktree_id,
                            force,
                        },
                    )
                    .await?
                    else {
                        bail!("daemon returned the wrong response to worktree prune");
                    };
                    if info.repository_id != repository_id || info.worktree_id != worktree_id {
                        bail!("daemon pruned another worktree");
                    }
                    println!("Pruned worktree {} at {}", worktree_id, info.path.display());
                }
                WorktreeCommand::Remove { worktree_id } => {
                    let LocalResponse::GitWorktreeRemoved(info) = local_control_call(
                        &socket,
                        &LocalRequest::GitWorktreeRemove {
                            repository_id,
                            worktree_id,
                        },
                    )
                    .await?
                    else {
                        bail!("daemon returned the wrong response to worktree remove");
                    };
                    if info.repository_id != repository_id || info.worktree_id != worktree_id {
                        bail!("daemon removed another worktree");
                    }
                    println!(
                        "Removed worktree {} at {}",
                        worktree_id,
                        info.path.display()
                    );
                }
            }
        }
        Command::Add {
            abort_pending,
            paths,
        } => {
            let (root, repository_id, worktree_id) = discover_location(&working_directory)?;
            for path in paths {
                let relative = relative_for_add(&root, &working_directory, &path)?;
                if abort_pending {
                    let request = match worktree_id {
                        Some(worktree_id) => LocalRequest::GitWorktreeAbandonPendingAdd {
                            repository_id,
                            worktree_id,
                            path: relative.clone(),
                        },
                        None => LocalRequest::GitAbandonPendingAdd {
                            repository_id,
                            path: relative.clone(),
                        },
                    };
                    let LocalResponse::GitPendingAddAbandoned { abandoned } =
                        local_control_call(&socket, &request).await?
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
                let request = match worktree_id {
                    Some(worktree_id) => LocalRequest::GitWorktreeAddPath {
                        repository_id,
                        worktree_id,
                        path: relative.clone(),
                    },
                    None => LocalRequest::GitAdd {
                        repository_id,
                        path: relative.clone(),
                    },
                };
                let response = local_control_call(&socket, &request).await?;
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
            let (root, repository_id, worktree_id) = discover_location(&working_directory)?;
            for path in paths {
                let relative = relative_for_add(&root, &working_directory, &path)?;
                let request = match (worktree_id, cached) {
                    (Some(worktree_id), true) => LocalRequest::GitWorktreeRemoveCached {
                        repository_id,
                        worktree_id,
                        path: relative.clone(),
                    },
                    (None, true) => LocalRequest::GitRemoveCached {
                        repository_id,
                        path: relative.clone(),
                    },
                    (Some(worktree_id), false) => LocalRequest::GitWorktreeRemoveTracked {
                        repository_id,
                        worktree_id,
                        path: relative.clone(),
                    },
                    (None, false) => LocalRequest::GitRemoveTracked {
                        repository_id,
                        path: relative.clone(),
                    },
                };
                let LocalResponse::GitCachedPathRemoved { removed } =
                    local_control_call(&socket, &request).await?
                else {
                    bail!("daemon returned the wrong response to Git index removal");
                };
                if !removed {
                    bail!("{} is not staged in the index", relative.display());
                }
                if cached {
                    println!("removed {} from index", relative.display());
                } else {
                    println!("removed {}", relative.display());
                }
            }
        }
        Command::Reset { hard, paths } => {
            if hard {
                if !paths.is_empty() {
                    bail!("`reset --hard` resets the whole worktree and takes no paths");
                }
                hard_reset(&socket, &working_directory).await?;
            } else {
                reset_index(&socket, &working_directory, paths).await?;
            }
        }
        Command::Restore {
            staged,
            worktree,
            paths,
        } => {
            if staged {
                reset_index(&socket, &working_directory, paths.clone()).await?;
            }
            if worktree || !staged {
                restore_worktree(&socket, &working_directory, paths).await?;
            }
        }
        Command::Commit {
            message,
            author_name,
            author_email,
        } => {
            let (_, repository_id, worktree_id) = discover_location(&working_directory)?;
            let author_name = author_name
                .map(Ok)
                .unwrap_or_else(|| author_field("GIT_AUTHOR_NAME", "user.name"))?;
            let author_email = author_email
                .map(Ok)
                .unwrap_or_else(|| author_field("GIT_AUTHOR_EMAIL", "user.email"))?;
            let request = match worktree_id {
                Some(worktree_id) => LocalRequest::GitWorktreeCommit {
                    repository_id,
                    worktree_id,
                    author_name,
                    author_email,
                    message,
                },
                None => LocalRequest::GitCommit {
                    repository_id,
                    author_name,
                    author_email,
                    message,
                },
            };
            let LocalResponse::GitCommitted(commit) = local_control_call(&socket, &request).await?
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
            let (_, repository_id, worktree_id) = discover_location(&working_directory)?;
            let request = match worktree_id {
                Some(worktree_id) => LocalRequest::GitWorktreeLog {
                    repository_id,
                    worktree_id,
                    limit,
                },
                None => LocalRequest::GitLog {
                    repository_id,
                    limit,
                },
            };
            let LocalResponse::GitLog(commits) = local_control_call(&socket, &request).await?
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
        Command::Branch {
            all,
            delete,
            force_delete,
            name,
            start_point,
        } => {
            let (_, repository_id, worktree_id) = discover_location(&working_directory)?;
            if let Some(name) = name {
                if all {
                    bail!("branch -a lists refs; omit -a when changing a branch");
                }
                if delete || force_delete {
                    if start_point.is_some() {
                        bail!("branch deletion does not accept a start point");
                    }
                    let request = match worktree_id {
                        Some(worktree_id) => LocalRequest::GitWorktreeDeleteBranch {
                            repository_id,
                            worktree_id,
                            name,
                            force: force_delete,
                        },
                        None => LocalRequest::GitDeleteBranch {
                            repository_id,
                            name,
                            force: force_delete,
                        },
                    };
                    let LocalResponse::GitBranchDeleted(branch) =
                        local_control_call(&socket, &request).await?
                    else {
                        bail!("daemon returned the wrong response to Git branch deletion");
                    };
                    if branch.repository_id != repository_id || branch.current {
                        bail!("daemon deleted an unexpected Git branch");
                    }
                    println!(
                        "Deleted branch {} (was {})",
                        branch.name,
                        git2::Oid::from_bytes(&branch.oid)?
                    );
                    return Ok(());
                }
                let request = match (worktree_id, start_point) {
                    (Some(worktree_id), Some(start_point)) => {
                        LocalRequest::GitWorktreeCreateBranchFrom {
                            repository_id,
                            worktree_id,
                            name,
                            start_point,
                        }
                    }
                    (Some(worktree_id), None) => LocalRequest::GitWorktreeCreateBranch {
                        repository_id,
                        worktree_id,
                        name,
                    },
                    (None, Some(start_point)) => LocalRequest::GitCreateBranchFrom {
                        repository_id,
                        name,
                        start_point,
                    },
                    (None, None) => LocalRequest::GitCreateBranch {
                        repository_id,
                        name,
                    },
                };
                let LocalResponse::GitBranchCreated(branch) =
                    local_control_call(&socket, &request).await?
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
                if delete || force_delete {
                    bail!("a branch name is required for deletion");
                }
                if start_point.is_some() {
                    bail!("a branch name is required before a start point");
                }
                let request = match worktree_id {
                    Some(worktree_id) => LocalRequest::GitWorktreeBranches {
                        repository_id,
                        worktree_id,
                    },
                    None => LocalRequest::GitBranches { repository_id },
                };
                let LocalResponse::GitBranches(branches) =
                    local_control_call(&socket, &request).await?
                else {
                    bail!("daemon returned the wrong response to Git branch listing");
                };
                for branch in branches {
                    if branch.repository_id != repository_id {
                        bail!("daemon listed a branch from another repository");
                    }
                    println!("{} {}", if branch.current { '*' } else { ' ' }, branch.name);
                }
                if all {
                    let LocalResponse::GitRemoteBranches(remotes) = local_control_call(
                        &socket,
                        &LocalRequest::GitRemoteBranches { repository_id },
                    )
                    .await?
                    else {
                        bail!("daemon returned the wrong response to remote branch listing");
                    };
                    for remote in remotes {
                        if remote.repository_id != repository_id || remote.format_version != 1 {
                            bail!("daemon listed a remote branch from another repository");
                        }
                        println!("  remotes/{}", remote.name);
                    }
                }
            }
        }
        Command::Tag {
            delete,
            annotate,
            message,
            name,
            start_point,
        } => {
            let (_, repository_id, worktree_id) = discover_location(&working_directory)?;
            if let Some(name) = name {
                if delete {
                    if start_point.is_some() {
                        bail!("tag deletion does not accept a start point");
                    }
                    let LocalResponse::GitTagDeleted(tag) = local_control_call(
                        &socket,
                        &LocalRequest::GitDeleteTag {
                            repository_id,
                            name: name.clone(),
                        },
                    )
                    .await?
                    else {
                        bail!("daemon returned the wrong response to Git tag deletion");
                    };
                    if tag.repository_id != repository_id || tag.name != name {
                        bail!("daemon deleted an unexpected Git tag");
                    }
                    println!(
                        "Deleted tag {} (was {})",
                        tag.name,
                        git2::Oid::from_bytes(&tag.oid)?
                    );
                } else {
                    let request = if annotate {
                        LocalRequest::GitCreateAnnotatedTag {
                            repository_id,
                            worktree_id,
                            name: name.clone(),
                            start_point,
                            tagger_name: author_field("GIT_COMMITTER_NAME", "user.name")?,
                            tagger_email: author_field("GIT_COMMITTER_EMAIL", "user.email")?,
                            message: message.context("annotated tags require -m MESSAGE")?,
                        }
                    } else {
                        LocalRequest::GitCreateTag {
                            repository_id,
                            worktree_id,
                            name: name.clone(),
                            start_point,
                        }
                    };
                    let LocalResponse::GitTagCreated(tag) =
                        local_control_call(&socket, &request).await?
                    else {
                        bail!("daemon returned the wrong response to Git tag creation");
                    };
                    if tag.repository_id != repository_id || tag.name != name {
                        bail!("daemon created an unexpected Git tag");
                    }
                    println!(
                        "Created tag {} at {}",
                        tag.name,
                        git2::Oid::from_bytes(&tag.oid)?
                    );
                }
            } else {
                if delete || annotate || message.is_some() || start_point.is_some() {
                    bail!("a tag name is required");
                }
                let LocalResponse::GitTags(tags) =
                    local_control_call(&socket, &LocalRequest::GitTags { repository_id }).await?
                else {
                    bail!("daemon returned the wrong response to Git tag listing");
                };
                for tag in tags {
                    if tag.repository_id != repository_id || tag.format_version != 1 {
                        bail!("daemon listed a tag from another repository");
                    }
                    println!("{}", tag.name);
                }
            }
        }
        Command::Pin { oid } | Command::Unpin { oid } => {
            let repository_id = discover_shared_repository(&working_directory)?;
            let oid: [u8; 20] = git2::Oid::from_str(&oid)?.as_bytes().try_into()?;
            let pinned = pin_action;
            let request = if pinned {
                LocalRequest::GitPinCommit { repository_id, oid }
            } else {
                LocalRequest::GitUnpinCommit { repository_id, oid }
            };
            let LocalResponse::GitCommitPinChanged {
                repository_id: changed_repository,
                oid: changed_oid,
                pinned: changed_pinned,
            } = local_control_call(&socket, &request).await?
            else {
                bail!("daemon returned the wrong response to Git pin change");
            };
            if changed_repository != repository_id || changed_oid != oid || changed_pinned != pinned
            {
                bail!("daemon changed an unexpected Git commit pin");
            }
            println!(
                "{} {}",
                if pinned { "Pinned" } else { "Unpinned" },
                git2::Oid::from_bytes(&oid)?
            );
        }
        Command::Pins => {
            let repository_id = discover_shared_repository(&working_directory)?;
            let LocalResponse::GitCommitPins {
                repository_id: listed_repository,
                oids,
            } = local_control_call(&socket, &LocalRequest::GitCommitPins { repository_id }).await?
            else {
                bail!("daemon returned the wrong response to Git pin listing");
            };
            if listed_repository != repository_id {
                bail!("daemon listed pins from another repository");
            }
            for oid in oids {
                println!("{}", git2::Oid::from_bytes(&oid)?);
            }
        }
        Command::Prune => {
            let repository_id = discover_shared_repository(&working_directory)?;
            let LocalResponse::GitPruned(report) =
                local_control_call(&socket, &LocalRequest::GitPrune { repository_id }).await?
            else {
                bail!("daemon returned the wrong response to Git prune");
            };
            if report.repository_id != repository_id || report.format_version != 1 {
                bail!("daemon returned an invalid Git prune report");
            }
            println!(
                "Pruned {} metadata object(s) and {} native anchor(s) ({} logical bytes)",
                report.metadata_objects_removed,
                report.native_anchors_removed,
                report.logical_anchor_bytes_removed
            );
            match report.physical_bytes_reclaimed {
                Some(bytes) => println!("Physical bytes reclaimed: {bytes}"),
                None => println!("Physical bytes reclaimed: not measured"),
            }
        }
        Command::Switch { name } | Command::Checkout { name } => {
            let (_, repository_id, worktree_id) = discover_location(&working_directory)?;
            let request = match worktree_id {
                Some(worktree_id) => LocalRequest::GitWorktreeSwitchBranch {
                    repository_id,
                    worktree_id,
                    name,
                },
                None => LocalRequest::GitSwitchBranch {
                    repository_id,
                    name,
                },
            };
            let LocalResponse::GitBranchSelected(branch) =
                local_control_call(&socket, &request).await?
            else {
                bail!("daemon returned the wrong response to Git switch");
            };
            if branch.repository_id != repository_id || !branch.current {
                bail!("daemon selected a branch in another repository");
            }
            println!("Switched to branch '{}'", branch.name);
        }
        Command::Push {
            destination,
            refspec,
        } => {
            let (_, repository_id, worktree_id) = discover_location(&working_directory)?;
            let destination = working_directory
                .join(destination)
                .canonicalize()
                .context("cannot resolve bare Git destination")?;
            let parsed = refspec.as_deref().map(parse_push_refspec).transpose()?;
            let request = match &parsed {
                Some(PushRefspec::Tag(name)) => LocalRequest::GitPushTagBare {
                    repository_id,
                    path: destination.clone(),
                    name: name.to_owned(),
                },
                Some(PushRefspec::Branch { source, target }) => LocalRequest::GitPushBranchBare {
                    repository_id,
                    path: destination.clone(),
                    source_branch: source.to_owned(),
                    target_branch: target.to_owned(),
                },
                None => match worktree_id {
                    Some(worktree_id) => LocalRequest::GitWorktreePushBare {
                        repository_id,
                        worktree_id,
                        path: destination.clone(),
                    },
                    None => LocalRequest::GitPushBare {
                        repository_id,
                        path: destination.clone(),
                    },
                },
            };
            let LocalResponse::GitPushed {
                repository_id: returned_id,
                oid,
            } = local_control_call(&socket, &request).await?
            else {
                bail!("daemon returned the wrong response to Git push");
            };
            if returned_id != repository_id {
                bail!("daemon pushed another repository");
            }
            match parsed {
                Some(PushRefspec::Tag(name)) => println!(
                    "Pushed tag {name} ({}) to {}",
                    git2::Oid::from_bytes(&oid)?,
                    destination.display()
                ),
                Some(PushRefspec::Branch { source, target }) => println!(
                    "Pushed {source} to {target} ({}) in {}",
                    git2::Oid::from_bytes(&oid)?,
                    destination.display()
                ),
                None => println!(
                    "Pushed {} to {}",
                    git2::Oid::from_bytes(&oid)?,
                    destination.display()
                ),
            }
        }
        Command::Fetch { source } => {
            let repository_id = discover_shared_repository(&working_directory)?;
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
                "Fetched {branch_count} branch(es) and available tags from {}",
                source.display()
            );
        }
        Command::Pull {
            source,
            author_name,
            author_email,
        } => {
            let (_, repository_id) = discover_repository(&working_directory)?;
            let source = working_directory.join(source);
            let author_name = match author_name {
                Some(value) => value,
                None => optional_author_field("GIT_AUTHOR_NAME", "user.name")?.unwrap_or_default(),
            };
            let author_email = match author_email {
                Some(value) => value,
                None => {
                    optional_author_field("GIT_AUTHOR_EMAIL", "user.email")?.unwrap_or_default()
                }
            };
            let LocalResponse::GitPulled {
                repository_id: returned_id,
                oid,
            } = local_control_call(
                &socket,
                &LocalRequest::GitPullBare {
                    repository_id,
                    path: source.clone(),
                    author_name,
                    author_email,
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
        Command::Merge {
            branch,
            continue_merge,
            abort,
            author_name,
            author_email,
        } => {
            let (_, repository_id) = discover_repository(&working_directory)?;
            if abort {
                let LocalResponse::GitMergeAborted {
                    repository_id: returned_id,
                } = local_control_call(&socket, &LocalRequest::GitMergeAbort { repository_id })
                    .await?
                else {
                    bail!("daemon returned the wrong response to Git merge --abort");
                };
                if returned_id != repository_id {
                    bail!("daemon aborted another repository's merge");
                }
                println!("Aborted pending merge; worktree and index edits remain");
                return Ok(());
            }
            if continue_merge {
                let LocalResponse::GitMerged {
                    repository_id: returned_id,
                    oid,
                } = local_control_call(&socket, &LocalRequest::GitMergeContinue { repository_id })
                    .await?
                else {
                    bail!("daemon returned the wrong response to Git merge --continue");
                };
                if returned_id != repository_id {
                    bail!("daemon merged another repository");
                }
                println!("Merge continued at {}", git2::Oid::from_bytes(&oid)?);
                return Ok(());
            }
            let branch = branch
                .ok_or_else(|| anyhow::anyhow!("merge needs a branch, --continue, or --abort"))?;
            let author_name = match author_name {
                Some(value) => value,
                None => optional_author_field("GIT_AUTHOR_NAME", "user.name")?.unwrap_or_default(),
            };
            let author_email = match author_email {
                Some(value) => value,
                None => {
                    optional_author_field("GIT_AUTHOR_EMAIL", "user.email")?.unwrap_or_default()
                }
            };
            let LocalResponse::GitMerged {
                repository_id: returned_id,
                oid,
            } = local_control_call(
                &socket,
                &LocalRequest::GitMergeBranch {
                    repository_id,
                    branch: branch.clone(),
                    author_name,
                    author_email,
                },
            )
            .await?
            else {
                bail!("daemon returned the wrong response to Git merge");
            };
            if returned_id != repository_id {
                bail!("daemon merged another repository");
            }
            println!("Merged '{}' at {}", branch, git2::Oid::from_bytes(&oid)?);
        }
        Command::Diff { cached } => {
            let (_, repository_id, worktree_id) = discover_location(&working_directory)?;
            let request = match worktree_id {
                Some(worktree_id) => LocalRequest::GitWorktreeDiff {
                    repository_id,
                    worktree_id,
                    cached,
                },
                None => LocalRequest::GitDiff {
                    repository_id,
                    cached,
                },
            };
            let LocalResponse::GitDiff(diff) = local_control_call(&socket, &request).await? else {
                bail!("daemon returned the wrong response to Git diff");
            };
            if diff.repository_id != repository_id || diff.cached != cached {
                bail!("daemon returned a diff for another repository or comparison");
            }
            io::stdout().write_all(&diff.patch)?;
        }
        Command::Status => {
            let (_, repository_id, worktree_id) = discover_location(&working_directory)?;
            let request = match worktree_id {
                Some(worktree_id) => LocalRequest::GitWorktreeStatus {
                    repository_id,
                    worktree_id,
                },
                None => LocalRequest::GitStatus { repository_id },
            };
            let LocalResponse::GitStatus(status) = local_control_call(&socket, &request).await?
            else {
                bail!("daemon returned the wrong response to Git status");
            };
            if status.repository_id != repository_id {
                bail!("daemon returned status for another repository");
            }
            println!("On branch {}", status.branch);
            println!("Content conversion: disabled (raw file bytes)");
            if status.head_oid.is_some() {
                if status.history_backed_up {
                    println!("Commit graph and refs are protected by a signed backup");
                } else {
                    println!("Commit graph or refs are awaiting a signed backup");
                }
            }
            if let Some(merge) = &status.merge {
                println!("Merge pending from {}", display_path(&merge.source_ref));
                for path in &merge.unresolved_paths {
                    println!("unresolved {}", display_path(path));
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

fn optional_author_field(environment: &str, config_key: &str) -> Result<Option<String>> {
    if let Some(value) = std::env::var_os(environment) {
        return Ok(Some(value.into_string().map_err(|_| {
            anyhow::anyhow!("{environment} is not valid UTF-8")
        })?));
    }
    match git2::Config::open_default()?.get_string(config_key) {
        Ok(value) => Ok(Some(value)),
        Err(error) if error.code() == git2::ErrorCode::NotFound => Ok(None),
        Err(error) => Err(error.into()),
    }
}

fn discover_repository(start: &Path) -> Result<(PathBuf, Uuid)> {
    let (root, repository_id, worktree_id) = discover_location(start)?;
    if worktree_id.is_some() {
        bail!("this command is not yet supported in a linked worktree");
    }
    Ok((root, repository_id))
}

fn discover_shared_repository(start: &Path) -> Result<Uuid> {
    Ok(discover_location(start)?.1)
}

fn discover_location(start: &Path) -> Result<(PathBuf, Uuid, Option<Uuid>)> {
    for directory in start.ancestors() {
        if let Some(scope) = linked_worktree_marker(directory)? {
            return Ok((
                directory.to_path_buf(),
                scope.repository_id(),
                Some(scope.worktree_id()),
            ));
        }
        if let Some(repository_id) = git_catalog_marker(directory)? {
            return Ok((directory.to_path_buf(), repository_id, None));
        }
    }
    bail!("no initialized MutualBackup Git repository contains this directory")
}

async fn reset_index(socket: &Path, working_directory: &Path, paths: Vec<PathBuf>) -> Result<()> {
    let (root, repository_id, worktree_id) = discover_location(working_directory)?;
    let paths = paths
        .iter()
        .map(|path| relative_for_add(&root, working_directory, path))
        .collect::<Result<Vec<_>>>()?;
    let request = match worktree_id {
        Some(worktree_id) => LocalRequest::GitWorktreeResetIndex {
            repository_id,
            worktree_id,
            paths,
        },
        None => LocalRequest::GitResetIndex {
            repository_id,
            paths,
        },
    };
    let LocalResponse::GitIndexReset {
        repository_id: returned_id,
        changed_paths,
    } = local_control_call(socket, &request).await?
    else {
        bail!("daemon returned the wrong response to Git index reset");
    };
    if returned_id != repository_id {
        bail!("daemon reset another repository's index");
    }
    println!("Reset {changed_paths} staged path(s) to HEAD");
    Ok(())
}

async fn restore_worktree(
    socket: &Path,
    working_directory: &Path,
    paths: Vec<PathBuf>,
) -> Result<()> {
    let (root, repository_id, worktree_id) = discover_location(working_directory)?;
    let paths = paths
        .iter()
        .map(|path| relative_for_add(&root, working_directory, path))
        .collect::<Result<Vec<_>>>()?;
    let request = match worktree_id {
        Some(worktree_id) => LocalRequest::GitWorktreeRestore {
            repository_id,
            worktree_id,
            paths,
        },
        None => LocalRequest::GitRestoreWorktree {
            repository_id,
            paths,
        },
    };
    let LocalResponse::GitWorktreeRestored {
        repository_id: returned_id,
        changed_paths,
    } = local_control_call(socket, &request).await?
    else {
        bail!("daemon returned the wrong response to Git worktree restore");
    };
    if returned_id != repository_id {
        bail!("daemon restored another repository's worktree");
    }
    println!("Restored {changed_paths} working path(s) from the index");
    Ok(())
}

async fn hard_reset(socket: &Path, working_directory: &Path) -> Result<()> {
    let (_, repository_id, worktree_id) = discover_location(working_directory)?;
    let request = match worktree_id {
        Some(worktree_id) => LocalRequest::GitWorktreeHardReset {
            repository_id,
            worktree_id,
        },
        None => LocalRequest::GitHardReset { repository_id },
    };
    let LocalResponse::GitHardResetCompleted {
        repository_id: returned_id,
        changed_paths,
    } = local_control_call(socket, &request).await?
    else {
        bail!("daemon returned the wrong response to Git hard reset");
    };
    if returned_id != repository_id {
        bail!("daemon reset another repository's worktree");
    }
    println!("Reset {changed_paths} tracked path(s) to HEAD");
    Ok(())
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

#[derive(Debug, Eq, PartialEq)]
enum PushRefspec {
    Branch { source: String, target: String },
    Tag(String),
}

fn parse_push_refspec(value: &str) -> Result<PushRefspec> {
    if value.starts_with('+') {
        bail!("force push is not supported");
    }
    let (source, target) = value.split_once(':').unwrap_or((value, value));
    if source.is_empty() || target.is_empty() || target.contains(':') {
        bail!("push refspec must name one source and destination ref");
    }
    if let Some(name) = source.strip_prefix("refs/tags/") {
        if name.is_empty() || target != source || !git2::Reference::is_valid_name(source) {
            bail!("tag push must use the same refs/tags/NAME on both sides");
        }
        return Ok(PushRefspec::Tag(name.to_owned()));
    }
    let source = source.strip_prefix("refs/heads/").unwrap_or(source);
    let target = target.strip_prefix("refs/heads/").unwrap_or(target);
    if source.starts_with("refs/")
        || target.starts_with("refs/")
        || !git2::Branch::name_is_valid(source)?
        || !git2::Branch::name_is_valid(target)?
    {
        bail!("push refspec must name valid local and destination branches");
    }
    Ok(PushRefspec::Branch {
        source: source.to_owned(),
        target: target.to_owned(),
    })
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

    #[test]
    fn push_refspecs_keep_branch_and_tag_namespaces_separate() {
        assert_eq!(
            parse_push_refspec("topic:review/topic").unwrap(),
            PushRefspec::Branch {
                source: "topic".to_owned(),
                target: "review/topic".to_owned(),
            }
        );
        assert_eq!(
            parse_push_refspec("refs/heads/topic:refs/heads/review/topic").unwrap(),
            PushRefspec::Branch {
                source: "topic".to_owned(),
                target: "review/topic".to_owned(),
            }
        );
        assert_eq!(
            parse_push_refspec("refs/tags/release").unwrap(),
            PushRefspec::Tag("release".to_owned())
        );
        for unsupported in [
            "+topic:main",
            "topic:",
            ":main",
            "topic:refs/tags/release",
            "refs/tags/release:refs/tags/other",
            "refs/remotes/origin/topic:main",
            "topic:main:extra",
        ] {
            assert!(parse_push_refspec(unsupported).is_err(), "{unsupported}");
        }
    }

    #[test]
    fn linked_marker_discovers_shared_repository_without_routing_primary_only_commands() {
        use std::os::unix::fs::PermissionsExt;

        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("linked");
        let nested = root.join("nested");
        let metadata = root.join(".mutualbackup");
        std::fs::create_dir_all(&nested).unwrap();
        std::fs::create_dir(&metadata).unwrap();
        std::fs::set_permissions(&metadata, std::fs::Permissions::from_mode(0o700)).unwrap();
        let repository_id = Uuid::new_v4();
        let worktree_id = Uuid::new_v4();
        std::fs::write(
            metadata.join("worktree"),
            format!("mutualbackup-git-worktree-v1\n{repository_id}\n{worktree_id}\n"),
        )
        .unwrap();
        assert_eq!(
            discover_location(&nested).unwrap(),
            (root, repository_id, Some(worktree_id))
        );
        assert_eq!(discover_shared_repository(&nested).unwrap(), repository_id);
        assert!(discover_repository(&nested).is_err());
    }
}
