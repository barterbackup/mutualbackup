use super::*;

#[tokio::test]
#[ignore = "requires an explicitly provisioned Btrfs test filesystem"]
async fn fresh_coordinator_routes_virtual_zero_openings_and_commits_backup() {
    let root = std::env::var_os("MUTUALBACKUP_REFLINK_TEST_ROOT")
        .expect("the native acceptance harness must provide Btrfs");
    let temp = tempfile::tempdir_in(root).unwrap();
    if let Err(error) = virtual_zero_backup(temp.path()).await {
        let preserved = temp.keep();
        panic!("virtual-zero coding failed: {error:#}; preserved={preserved:?}");
    }
}

async fn virtual_zero_backup(root: &std::path::Path) -> Result<()> {
    let seeds = (201_u8..206)
        .map(|byte| Seed::from_bytes([byte; 32]))
        .collect::<Vec<_>>();
    let nodes = seeds
        .iter()
        .enumerate()
        .map(|(index, seed)| {
            Ok(Arc::new(Mutex::new(Node::open(
                root.join(format!("node-{index}")),
                seed.clone(),
            )?)))
        })
        .collect::<Result<Vec<_>>>()?;
    let ids = nodes
        .iter()
        .map(|node| node.lock().unwrap().keys().node_id())
        .collect::<Vec<_>>();
    let mut clients = Vec::new();
    let mut tasks = Vec::new();
    for (node, id) in nodes.iter().zip(&ids) {
        let mut cfg = config(*id);
        cfg.enable_dht_maintenance = false;
        cfg.enable_relay_server = false;
        let (client, event_loop) = build_p2p(node.clone(), cfg)?;
        clients.push(client);
        tasks.push(Some(tokio::spawn(event_loop.run())));
    }
    let addresses = futures::future::join_all(clients.iter().map(listening_address)).await;
    let endpoints = clients
        .iter()
        .zip(&addresses)
        .map(|(client, address)| peer_endpoint(client, address.clone()))
        .collect::<Vec<_>>();
    form_test_guild(&nodes, &clients, &addresses, &endpoints).await;

    let source = root.join("source");
    std::fs::create_dir(&source)?;
    let original = b"native backup must retain exact\r\n\0bytes";
    std::fs::write(source.join("payload"), original)?;
    // Three encrypted source sectors (two files and metadata) produce a
    // partially occupied final coding lane under the normal packing policy.
    std::fs::write(source.join("second"), b"second native file\r\n\0")?;
    let captured_source = source.clone();
    let descriptor = node_blocking(nodes[0].clone(), move |node| {
        node.add_protected_root(&captured_source)?;
        node.prepare_protected_backup(None)
    })
    .await?;
    let submission = descriptor.clone();
    let job = node_blocking(nodes[0].clone(), move |node| {
        node.enqueue_backup(node.keys().node_id(), submission)
    })
    .await?;
    let backup_node = nodes[0].clone();
    let backup_client = clients[0].clone();
    let backup =
        tokio::spawn(async move { commit_backup_job(backup_node, &backup_client, &job).await });
    let mut launch = tokio::time::timeout(Duration::from_secs(120), async {
        loop {
            let launches =
                node_blocking(nodes[0].clone(), |node| node.coding_launch_jobs_for_test()).await?;
            if let Some(launch) = launches.into_iter().find(|launch| {
                launch
                    .plan
                    .value
                    .geometry
                    .information
                    .iter()
                    .any(|role| role.sector.virtual_zero && role.owner != ids[0])
            }) {
                break Ok::<_, anyhow::Error>(launch);
            }
            anyhow::ensure!(
                !backup.is_finished(),
                "backup ended before its coding launch"
            );
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    })
    .await
    .context("native backup did not queue a lane with a remote virtual-zero owner")??;

    // Fix coordinator selection in the undispatched fixture while retaining
    // the production planner's geometry, inputs, attempt ID and deadlines.
    // A parity participant codes; the delegator verifies. Neither can supply
    // the signatures assigned to virtual-only remote information owners.
    anyhow::ensure!(!launch.dispatched);
    let mut value = launch.plan.value.clone();
    value.coding_coordinator = value
        .geometry
        .parity
        .iter()
        .find(|role| role.holder != ids[0])
        .context("remote parity participant")?
        .holder;
    value.verification_coordinator = ids[0];
    let coding_index = ids
        .iter()
        .position(|id| *id == value.coding_coordinator)
        .unwrap();
    let remote_zero_owners = value
        .geometry
        .information
        .iter()
        .filter(|role| role.sector.virtual_zero && role.owner != ids[0])
        .map(|role| role.owner)
        .collect::<BTreeSet<_>>();
    anyhow::ensure!(
        !remote_zero_owners.is_empty(),
        "fixture needs a virtual-only remote participant"
    );
    for owner in &remote_zero_owners {
        anyhow::ensure!(*owner != value.coding_coordinator);
        anyhow::ensure!(
            value
                .geometry
                .parity
                .iter()
                .all(|role| role.holder != *owner)
        );
        anyhow::ensure!(
            value
                .geometry
                .information
                .iter()
                .all(|role| role.owner != *owner || role.sector.virtual_zero)
        );
    }
    launch.plan = node_blocking(nodes[0].clone(), move |node| {
        node.sign_coding_attempt_plan(value)
    })
    .await?;
    let pinned_launch = launch.clone();
    node_blocking(nodes[0].clone(), move |node| {
        node.install_coding_launch_for_test(&pinned_launch)
    })
    .await?;
    let plan = launch.plan.clone();
    anyhow::ensure!(dispatch_claimed_coding_launch(nodes[0].clone(), &clients[0], launch).await?);

    clients[coding_index].shutdown().await?;
    tasks[coding_index].take().unwrap().await??;
    let mut cfg = config(ids[coding_index]);
    cfg.enable_dht_maintenance = false;
    cfg.enable_relay_server = false;
    // Use a new listener; the old QUIC socket may still be draining. Every
    // application participant will have the coder's authenticated outbound
    // connection before activation, so no stale listener is needed for it.
    let (fresh, mut routing) = build_p2p(nodes[coding_index].clone(), cfg)?;
    for owner in &remote_zero_owners {
        anyhow::ensure!(
            routing
                .retained_peer_addresses(owner.libp2p_peer_id()?)
                .is_empty()
        );
    }
    let delegated = node_blocking(nodes[coding_index].clone(), |node| {
        node.claim_delegated_coding()
    })
    .await?
    .context("persisted delegated job")?;
    anyhow::ensure!(delegated.plan == plan);
    let execution = execute_delegated_coding(nodes[coding_index].clone(), &fresh, &delegated);
    tokio::pin!(execution);
    // Never poll this swarm before inspecting the first RPC. Discovery,
    // Identify and an incoming connection cannot incidentally supply routes.
    tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            let command = tokio::select! {
                result = &mut execution => bail!("coding ended before its first RPC: {result:?}"),
                command = routing.commands.recv() => command.context("coding command channel closed")?,
            };
            if let Command::Request { recipient, .. } = &command {
                anyhow::ensure!(*recipient == plan.value.verification_coordinator);
                let routes = remote_zero_owners.iter().map(|owner| {
                    Ok((owner.to_string(), routing.retained_peer_addresses(owner.libp2p_peer_id()?).iter().map(ToString::to_string).collect::<Vec<_>>()))
                }).collect::<Result<BTreeMap<_, _>>>()?;
                std::fs::write(root.join("zero-owner-routes.json"), serde_json::to_vec_pretty(&routes)?)?;
                anyhow::ensure!(routes.values().all(|addresses| !addresses.is_empty()), "virtual-zero owner lacks its roster route before the first coding RPC");
                routing.handle_command(command)?;
                break Ok::<_, anyhow::Error>(());
            }
            routing.handle_command(command)?;
        }
    }).await.context("coding did not reach its first RPC")??;
    tasks[coding_index] = Some(tokio::spawn(routing.run()));
    clients[coding_index] = fresh.clone();
    let transcript = tokio::time::timeout(Duration::from_secs(90), execution)
        .await
        .context("coding did not obtain every signed opening")??;
    anyhow::ensure!(transcript.value.plan == plan);
    anyhow::ensure!(
        replay_coding_transcript(&transcript)? == mb_core::CodingReplayFinding::Verified
    );
    for owner in &remote_zero_owners {
        let index = plan
            .value
            .geometry
            .information
            .iter()
            .position(|role| role.owner == *owner)
            .unwrap();
        let opening = transcript
            .value
            .openings
            .iter()
            .find(|opening| usize::from(opening.value.shard_index) == index)
            .context("virtual-zero opening missing")?;
        opening.verify(CODING_SHARD_OPENING_DOMAIN)?;
        anyhow::ensure!(opening.signer == *owner);
        anyhow::ensure!(opening.value.proof.leaves == vec![[0; MERKLE_LEAF_SIZE]]);
    }
    let attempt_id = plan.value.attempt_id;
    let result = transcript.clone();
    node_blocking(nodes[coding_index].clone(), move |node| {
        node.record_delegated_coding_result(attempt_id, result)
    })
    .await?;
    process_delegated_coding_job(nodes[coding_index].clone(), &fresh).await?;
    process_coding_activation_job(nodes[0].clone(), &clients[0]).await?;
    let group_id = transcript.value.manifest.value.group.id;
    node_blocking(nodes[0].clone(), move |node| {
        anyhow::ensure!(node.coding_activation_jobs_for_test()?.iter().any(|job| job.complete && job.transcript.value.plan.value.attempt_id == attempt_id));
        anyhow::ensure!(node.dynamic_guild_state()?.unwrap().coding_groups.iter().any(|group| group.group.id == group_id && group.retired_at_event.is_none()));
        Ok(())
    }).await?;
    // The remaining production lanes also have to finish; the route probe
    // does not replace the complete backup with a tail-lane-only assertion.
    let workers = nodes
        .iter()
        .zip(&clients)
        .map(|(node, client)| tokio::spawn(run_delegated_coding_jobs(node.clone(), client.clone())))
        .collect::<Vec<_>>();
    let checkpoint_hash = tokio::time::timeout(Duration::from_secs(240), backup)
        .await
        .context("native backup did not commit after verified coding")???;
    let submitted = descriptor.clone();
    node_blocking(nodes[0].clone(), move |node| {
        node.complete_backup_job(&submitted, checkpoint_hash)
    })
    .await?;
    for worker in workers {
        worker.abort();
        anyhow::ensure!(worker.await.unwrap_err().is_cancelled());
    }
    for client in &clients {
        client.shutdown().await?;
    }
    for task in tasks.into_iter().flatten() {
        task.await??;
    }
    drop((clients, nodes));
    let node = tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            match Node::open(root.join("node-0"), seeds[0].clone()) {
                Ok(node) => break Ok::<_, anyhow::Error>(node),
                Err(error)
                    if error
                        .to_string()
                        .contains("node data directory is already in use") =>
                {
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
                Err(error) => break Err(error),
            }
        }
    })
    .await
    .context("coding worker did not release the node after shutdown")??;
    let committed = node.backup_job(descriptor.guild_id, descriptor.revision_id)?;
    anyhow::ensure!(
        committed.state == crate::node::BackupJobState::Committed
            && committed.checkpoint_hash == Some(checkpoint_hash)
    );
    let checkpoint = node
        .current_checkpoint(descriptor.guild_id)?
        .context("committed checkpoint missing after reopen")?;
    checkpoint.verify()?;
    anyhow::ensure!(
        checkpoint.hash()? == checkpoint_hash && checkpoint.checkpoint.format_version == 7
    );
    anyhow::ensure!(
        checkpoint
            .checkpoint
            .revisions
            .iter()
            .any(|revision| revision.value.revision_id == descriptor.revision_id)
    );
    anyhow::ensure!(
        node.coding_activation_jobs_for_test()?
            .iter()
            .any(|job| job.complete && job.transcript == transcript)
    );
    anyhow::ensure!(std::fs::read(source.join("payload"))? == original);
    anyhow::ensure!(std::fs::read(source.join("second"))? == b"second native file\r\n\0");
    Ok(())
}
