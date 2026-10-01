//! Stock Git fetch/push bridge for `mutualbackup::<absolute-repository-path>`.
//! Git owns its local object database; the daemon streams native anchor bytes
//! in either direction without a persistent Git mirror on our side.

use std::env;
use std::io::{self, BufRead, Write};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use git2::Oid;
use mb_git::GitBranchInfo;
use mb_node::{LocalRequest, LocalResponse, local_control_call};
use mb_store::git_catalog_marker;
use mutualbackup::default_control_socket;
use uuid::Uuid;

const MAX_PROTOCOL_LINE: usize = 4096;
const MAX_ADVERTISED_REFS: usize = 4096;
const MAX_ADVERTISED_NAME_BYTES: usize = 256 * 1024;

fn read_line(input: &mut impl BufRead) -> Result<Option<String>> {
    let mut line = Vec::new();
    loop {
        let available = input.fill_buf()?;
        if available.is_empty() {
            if line.is_empty() {
                return Ok(None);
            }
            bail!("unterminated Git remote-helper command");
        }
        let count = available
            .iter()
            .position(|byte| *byte == b'\n')
            .map_or(available.len(), |index| index + 1);
        if line.len() + count > MAX_PROTOCOL_LINE {
            bail!("Git remote-helper command exceeds the local bound");
        }
        let ended = available[count - 1] == b'\n';
        line.extend_from_slice(&available[..count]);
        input.consume(count);
        if ended {
            line.pop();
            return Ok(Some(String::from_utf8(line)?));
        }
    }
}

fn repository_from_url(url: &str) -> Result<(PathBuf, Uuid)> {
    let path = Path::new(url);
    if !path.is_absolute() {
        bail!("mutualbackup remote URL must be an absolute repository path");
    }
    let path = path
        .canonicalize()
        .context("cannot resolve remote repository")?;
    let repository_id =
        git_catalog_marker(&path)?.context("remote path is not a MutualBackup Git repository")?;
    Ok((path, repository_id))
}

fn destination_git_directory() -> Result<PathBuf> {
    let path = env::var_os("GIT_DIR").context("Git did not set GIT_DIR for its remote helper")?;
    PathBuf::from(path)
        .canonicalize()
        .context("cannot resolve the stock Git object database")
}

fn validate_branches(branches: &[GitBranchInfo], repository_id: Uuid) -> Result<()> {
    if branches.len() > MAX_ADVERTISED_REFS
        || branches
            .iter()
            .map(|branch| branch.name.len())
            .sum::<usize>()
            > MAX_ADVERTISED_NAME_BYTES
    {
        bail!("too many Git refs to advertise through the local helper");
    }
    let mut seen = std::collections::HashSet::new();
    for branch in branches {
        if branch.format_version != 1
            || branch.repository_id != repository_id
            || !git2::Branch::name_is_valid(&branch.name)?
            || !seen.insert(&branch.name)
        {
            bail!("daemon returned an incompatible Git branch advertisement");
        }
    }
    Ok(())
}

fn validate_fetch(line: &str, branches: &[GitBranchInfo]) -> Result<()> {
    let mut fields = line.split(' ');
    let (Some("fetch"), Some(oid), Some(name), None) =
        (fields.next(), fields.next(), fields.next(), fields.next())
    else {
        bail!("unsupported Git remote-helper fetch command");
    };
    let oid = Oid::from_str(oid)?;
    if !branches
        .iter()
        .any(|branch| name == format!("refs/heads/{}", branch.name) && branch.oid == oid.as_bytes())
    {
        bail!("Git requested a ref that was not advertised");
    }
    Ok(())
}

async fn receive_push(
    line: &str,
    socket: &Path,
    repository_id: Uuid,
    source_root: &Path,
    source_git_directory: &Path,
    advertised: &[GitBranchInfo],
) -> Result<()> {
    let specification = line
        .strip_prefix("push ")
        .context("unsupported Git remote-helper push command")?;
    let (source, destination) = specification
        .split_once(':')
        .context("Git push needs a source and destination ref")?;
    let branch = destination
        .strip_prefix("refs/heads/")
        .context("only local branch refs can receive stock Git pushes")?;
    if source.is_empty()
        || source.starts_with('+')
        || branch.len() > 1024
        || !git2::Branch::name_is_valid(branch)?
    {
        bail!("forced pushes and branch deletion are not supported");
    }
    let stock = git2::Repository::open(source_git_directory)?;
    if stock.path().canonicalize()? != source_git_directory
        || stock.object_format() != git2::ObjectFormat::Sha1
    {
        bail!("stock Git source is not an exact SHA-1 repository");
    }
    let oid = stock.revparse_single(source)?.peel_to_commit()?.id();
    let expected_old = advertised
        .iter()
        .find(|entry| entry.name == branch)
        .map(|entry| entry.oid);
    let LocalResponse::GitPushReceived {
        repository_id: returned_id,
        branch: returned_branch,
        oid: returned_oid,
    } = local_control_call(
        socket,
        &LocalRequest::GitReceivePushedBranch {
            repository_id,
            source_root: source_root.to_path_buf(),
            source_git_directory: source_git_directory.to_path_buf(),
            target_branch: branch.to_owned(),
            target_oid: oid.as_bytes().try_into().expect("SHA-1 OID"),
            expected_old,
        },
    )
    .await?
    else {
        bail!("daemon returned the wrong Git push response");
    };
    if returned_id != repository_id || returned_branch != branch || returned_oid != oid.as_bytes() {
        bail!("daemon received another Git branch or object");
    }
    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    let mut arguments = env::args();
    let _program = arguments.next();
    let _remote_name = arguments.next().context("Git remote name is missing")?;
    let url = arguments.next().context("Git remote URL is missing")?;
    if arguments.next().is_some() {
        bail!("unexpected Git remote-helper argument");
    }
    let (source_root, repository_id) = repository_from_url(&url)?;
    let destination = destination_git_directory()?;
    let socket = env::var_os("MUTUALBACKUP_CONTROL_SOCKET")
        .map(PathBuf::from)
        .unwrap_or_else(default_control_socket);
    let stdin = io::stdin();
    let mut input = stdin.lock();
    let stdout = io::stdout();
    let mut output = stdout.lock();
    let mut advertised: Option<Vec<GitBranchInfo>> = None;
    while let Some(command) = read_line(&mut input)? {
        match command.as_str() {
            "capabilities" => {
                output.write_all(b"fetch\npush\n\n")?;
                output.flush()?;
            }
            "list" | "list for-push" => {
                let LocalResponse::GitBranches(branches) =
                    local_control_call(&socket, &LocalRequest::GitBranches { repository_id })
                        .await?
                else {
                    bail!("daemon returned the wrong Git branch response");
                };
                validate_branches(&branches, repository_id)?;
                for branch in &branches {
                    writeln!(
                        output,
                        "{} refs/heads/{}",
                        Oid::from_bytes(&branch.oid)?,
                        branch.name
                    )?;
                }
                if let Some(current) = branches.iter().find(|branch| branch.current) {
                    writeln!(output, "@refs/heads/{} HEAD", current.name)?;
                }
                output.write_all(b"\n")?;
                output.flush()?;
                advertised = Some(branches);
            }
            value if value.starts_with("fetch ") => {
                let branches = advertised
                    .as_ref()
                    .context("Git requested objects before listing remote refs")?;
                validate_fetch(value, branches)?;
                loop {
                    let next = read_line(&mut input)?
                        .context("Git closed an unfinished remote-helper fetch batch")?;
                    if next.is_empty() {
                        break;
                    }
                    validate_fetch(&next, branches)?;
                }
                let LocalResponse::GitObjectsExported {
                    repository_id: returned_id,
                    ..
                } = local_control_call(
                    &socket,
                    &LocalRequest::GitExportToGitRepository {
                        repository_id,
                        source_root: source_root.clone(),
                        destination: destination.clone(),
                        advertised: branches.clone(),
                    },
                )
                .await?
                else {
                    bail!("daemon returned the wrong Git object export response");
                };
                if returned_id != repository_id {
                    bail!("daemon exported objects from another repository");
                }
                output.write_all(b"\n")?;
                output.flush()?;
            }
            value if value.starts_with("push ") => {
                let branches = advertised
                    .as_ref()
                    .context("Git requested a push before listing remote refs")?;
                let mut commands = vec![value.to_owned()];
                loop {
                    let next = read_line(&mut input)?
                        .context("Git closed an unfinished remote-helper push batch")?;
                    if next.is_empty() {
                        break;
                    }
                    if !next.starts_with("push ") {
                        bail!("unsupported Git remote-helper push batch command");
                    }
                    commands.push(next);
                }
                for command in commands {
                    let destination_ref = command
                        .strip_prefix("push ")
                        .and_then(|specification| specification.split_once(':'))
                        .map(|(_, destination)| destination)
                        .context("Git push needs a destination ref")?;
                    match receive_push(
                        &command,
                        &socket,
                        repository_id,
                        &source_root,
                        &destination,
                        branches,
                    )
                    .await
                    {
                        Ok(_) => writeln!(output, "ok {destination_ref}")?,
                        Err(error) => {
                            let reason = format!("{error:#}").replace(['\n', '\r'], " ");
                            writeln!(output, "error {destination_ref} {reason}")?;
                        }
                    }
                }
                output.write_all(b"\n")?;
                output.flush()?;
            }
            "" => break,
            _ => bail!("unsupported Git remote-helper command: {command}"),
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fetch_requests_must_match_an_advertised_ref_and_oid() {
        let branch = GitBranchInfo {
            format_version: 1,
            repository_id: Uuid::new_v4(),
            name: "topic".to_owned(),
            oid: [7; 20],
            current: false,
        };
        let oid = Oid::from_bytes(&branch.oid).unwrap();
        validate_fetch(
            &format!("fetch {oid} refs/heads/topic"),
            std::slice::from_ref(&branch),
        )
        .unwrap();
        assert!(
            validate_fetch(
                &format!("fetch {oid} refs/heads/main"),
                std::slice::from_ref(&branch)
            )
            .is_err()
        );
        assert!(validate_fetch("fetch bad refs/heads/topic", &[branch]).is_err());
    }
}
