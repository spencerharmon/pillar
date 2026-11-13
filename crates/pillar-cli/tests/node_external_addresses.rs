//! Exercise configuration and the production node's first identify exchange.
#![cfg(feature = "acceptance")]

use futures::StreamExt;
use libp2p::{identity::Keypair, swarm::SwarmEvent, Multiaddr};
use pillar_cli::run::{ConfigError, NodeConfig};
use pillar_net::{build_event_swarm_with_root, EventBehaviourEvent, PrivateSwarmKey};
use std::process::{Child, Command, Stdio};
use std::time::Duration;

const TCP: &str = "/dns4/seed.example.com/tcp/41001";
const QUIC: &str = "/dns/seed.example.net/udp/41002/quic-v1";

#[test]
fn config_defaults_env_and_cli_precedence() {
    let defaults = NodeConfig::from_args_env(&[], |_| None).unwrap();
    assert!(defaults.external_addresses.is_empty());
    let expected: Vec<Multiaddr> = [TCP, QUIC].iter().map(|s| s.parse().unwrap()).collect();
    for separator in [",", " ", "\t", "\n", ", \t"] {
        let config = NodeConfig::from_args_env(&[], |key| {
            (key == "PILLAR_EXTERNAL_ADDRESSES").then(|| format!("{TCP}{separator}{QUIC}"))
        })
        .unwrap();
        assert_eq!(config.external_addresses, expected);
        assert_eq!(config.listen, defaults.listen);
        assert_eq!(config.dial, defaults.dial);
        assert_eq!(config.seed, defaults.seed);
        assert_eq!(config.upnp, defaults.upnp);
    }
    let args = ["--external-address", TCP, "--external-address", QUIC].map(String::from);
    let config = NodeConfig::from_args_env(&args, |key| {
        (key == "PILLAR_EXTERNAL_ADDRESSES").then(|| "invalid-env-overridden".into())
    })
    .unwrap();
    assert_eq!(config.external_addresses, expected);
    let empty = NodeConfig::from_args_env(&[], |key| {
        (key == "PILLAR_EXTERNAL_ADDRESSES").then(|| " ,\t\n".into())
    })
    .unwrap();
    assert_eq!(empty, defaults);
}

#[test]
fn rejects_invalid_external_addresses() {
    assert_eq!(
        NodeConfig::from_args_env(&["--external-address".into()], |_| None),
        Err(ConfigError::MissingValue("--external-address"))
    );
    for invalid in [
        "not-a-multiaddr",
        "/ip4/not-an-ip/tcp/42",
        "/dns/example.com/tcp/65536",
        "/unknown/value",
        "",
    ] {
        let args = ["--external-address".to_owned(), invalid.to_owned()];
        assert!(
            matches!(
                NodeConfig::from_args_env(&args, |_| None),
                Err(ConfigError::BadExternalAddress { .. })
            ),
            "CLI accepted {invalid:?}"
        );
        if !invalid.is_empty() {
            assert!(
                matches!(
                    NodeConfig::from_args_env(&[], |key| {
                        (key == "PILLAR_EXTERNAL_ADDRESSES").then(|| format!("{TCP},{invalid}"))
                    }),
                    Err(ConfigError::BadExternalAddress { .. })
                ),
                "environment accepted {invalid:?}"
            );
        }
    }
}

#[test]
fn external_addresses_do_not_replace_listen_seed_dial_or_upnp() {
    let args = [
        "--external-address",
        TCP,
        "--listen",
        "/ip4/127.0.0.1/tcp/0",
        "--dial",
        "/ip4/127.0.0.1/tcp/42001",
        "--seed-node",
        "/dnsaddr/bootstrap.example.com",
        "--upnp",
    ]
    .map(String::from);
    let config = NodeConfig::from_args_env(&args, |_| None).unwrap();
    assert_eq!(
        config.external_addresses,
        vec![TCP.parse::<Multiaddr>().unwrap()]
    );
    assert_eq!(
        config.listen,
        vec!["/ip4/127.0.0.1/tcp/0".parse::<Multiaddr>().unwrap()]
    );
    assert_eq!(
        config.dial,
        vec!["/ip4/127.0.0.1/tcp/42001".parse::<Multiaddr>().unwrap()]
    );
    assert_eq!(
        config.seed,
        vec!["/dnsaddr/bootstrap.example.com"
            .parse::<Multiaddr>()
            .unwrap()]
    );
    assert!(config.upnp);
}

struct Node(Child);

impl Drop for Node {
    fn drop(&mut self) {
        self.0.kill().expect("stop test-owned node");
        self.0.wait().expect("reap test-owned node");
    }
}

async fn identify_from_node(use_flags: bool) {
    let root = PrivateSwarmKey::from_root_secret(pillar_swarm::SwarmKey::public().root_secret());
    let mut observer = build_event_swarm_with_root(Keypair::generate_ed25519(), root, false, true)
        .expect("observer swarm");
    observer
        .listen_on("/ip4/127.0.0.1/tcp/0".parse().unwrap())
        .unwrap();
    let address = tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            if let SwarmEvent::NewListenAddr { address, .. } = observer.select_next_some().await {
                break address;
            }
        }
    })
    .await
    .expect("observer listens");
    let data = tempfile::tempdir().unwrap();
    let mut command = Command::new(env!("CARGO_BIN_EXE_pillar"));
    // Isolate from operator configuration without discarding PATH/HOME.
    for (key, _) in std::env::vars_os() {
        if key.to_string_lossy().starts_with("PILLAR_") {
            command.env_remove(key);
        }
    }
    command
        .args([
            "node",
            "run",
            "--listen",
            "/ip4/127.0.0.1/tcp/0",
            "--health-bind",
            "127.0.0.1",
            "--health-port",
            "0",
            "--seed-node",
            &address.to_string(),
        ])
        .arg("--data-dir")
        .arg(data.path())
        .env("PILLAR_UPNP", "false")
        .env("RUST_LOG", "error")
        .stdout(Stdio::null())
        .stderr(Stdio::inherit());
    if use_flags {
        command
            .args(["--external-address", TCP, "--external-address", QUIC])
            .env(
                "PILLAR_EXTERNAL_ADDRESSES",
                "/dns4/ignored.example.com/tcp/43001",
            );
    } else {
        command.env("PILLAR_EXTERNAL_ADDRESSES", format!("{TCP},{QUIC}"));
    }
    let mut node = Node(command.spawn().expect("spawn production node"));
    let received = tokio::time::timeout(Duration::from_secs(20), async {
        loop {
            if let SwarmEvent::Behaviour(EventBehaviourEvent::Identify(
                libp2p::identify::Event::Received { info, .. },
            )) = observer.select_next_some().await
            {
                break info.listen_addrs;
            }
        }
    })
    .await
    .expect("node must send its first identify response");
    for expected in [TCP, QUIC] {
        assert!(
            received.contains(&expected.parse().unwrap()),
            "identify omitted {expected}: {received:?}"
        );
    }
    assert!(!received.contains(&"/dns4/ignored.example.com/tcp/43001".parse().unwrap()));
    assert!(
        node.0.try_wait().unwrap().is_none(),
        "node must remain running"
    );
    // The advertised DNS names are deliberately not locally bindable. A real
    // identify response proves startup did not try to listen on these addresses.
}

#[tokio::test]
async fn cli_addresses_reach_a_real_peer_through_identify() {
    identify_from_node(true).await;
}

#[tokio::test]
async fn env_addresses_reach_a_real_peer_through_identify() {
    identify_from_node(false).await;
}
