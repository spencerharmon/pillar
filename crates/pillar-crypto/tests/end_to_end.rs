//! End-to-end key-distribution acceptance matrix.
//!
//! This is the executable definition of "the crypto works": every combination
//! the operator enumerated, walked through the public `pillar-crypto` API using
//! the shared principal infrastructure. Every case is RED until the primitives
//! are implemented; when they are green, the persistence story (pin the sealed
//! cell key to IPFS; never the private key) can build on top.

use pillar_crypto::cell::{
    cell_decrypt, cell_encrypt, distribute_group_key, group_key_from_seed, recover_group_key,
};
use pillar_crypto::node::node_unlock;
use pillar_crypto::principal::principal_from_seed;
use pillar_crypto::seal::{seal_to_recipients, unseal};
use pillar_crypto::user::{
    certify_subkey, open_message_from_user, open_signed_cell_message, seal_message_to_user,
    signed_cell_message, verify_subkey,
};
use pillar_crypto::{CellId, Seed};

fn seed(label: &str) -> Seed {
    Seed::from_bytes(format!("pillar-e2e::{label}").into_bytes())
}

/// Node keys unlock both cell keys and user keys sealed to the node.
#[test]
fn node_unlocks_cell_key_and_user_key() {
    let (node_pub, node_sec) = principal_from_seed(&seed("node-1")).expect("node");

    // (a) a cell group key sealed to the node.
    let group = group_key_from_seed(&seed("cellA-group")).expect("group");
    let sealed_group = distribute_group_key(&group, std::slice::from_ref(&node_pub.sealing))
        .expect("seal cell key");
    assert_eq!(
        recover_group_key(&sealed_group, &node_sec.sealing),
        Ok(group),
        "node unlocks the cell key"
    );

    // (b) a user private key blob sealed to the node.
    let user_key = b"argon2id-encrypted user private key blob";
    let sealed_user = seal_to_recipients(user_key, &[node_pub.sealing]).expect("seal user key");
    assert_eq!(
        node_unlock(&node_sec.sealing, &sealed_user).as_deref(),
        Ok(user_key.as_ref()),
        "node unlocks the user key"
    );
}

/// Cell keys encrypt the database and cell broadcast messages.
#[test]
fn cell_key_encrypts_database_and_broadcasts() {
    let group = group_key_from_seed(&seed("cellA")).expect("group");

    let db_record = b"streaming-db op #42: append member(bob, role=admin)";
    let rec_ct = cell_encrypt(&group, db_record, b"db").expect("encrypt db");
    assert_eq!(
        cell_decrypt(&group, &rec_ct, b"db").as_deref(),
        Ok(db_record.as_ref())
    );

    let broadcast = b"cell broadcast: topology changed, tier=edge";
    let bc_ct = cell_encrypt(&group, broadcast, b"broadcast").expect("encrypt broadcast");
    assert_eq!(
        cell_decrypt(&group, &bc_ct, b"broadcast").as_deref(),
        Ok(broadcast.as_ref())
    );
}

/// User keys sign and send a message encrypted for their cell.
#[test]
fn user_signs_and_sends_message_encrypted_for_their_cell() {
    let (alice_pub, alice_sec) = principal_from_seed(&seed("alice@cellA")).expect("alice subkey");
    let group = group_key_from_seed(&seed("cellA")).expect("group");

    let msg = b"team, deploying controller at epoch 9";
    let signed = signed_cell_message(&alice_sec.signing, &group, msg).expect("send to cell");
    assert_eq!(
        open_signed_cell_message(&group, &alice_pub.signing, &signed).as_deref(),
        Ok(msg.as_ref()),
        "a cell member verifies alice and reads the message"
    );
}

/// User-to-user direct message, within the same cell.
#[test]
fn user_to_user_within_a_cell() {
    let (_a_pub, a_sec) = principal_from_seed(&seed("alice@cellA")).expect("alice");
    let (a_pub, _) = principal_from_seed(&seed("alice@cellA")).expect("alice pub");
    let (bob_pub, bob_sec) = principal_from_seed(&seed("bob@cellA")).expect("bob");

    let msg = b"bob, ack the rollout?";
    let dm = seal_message_to_user(&a_sec.signing, &bob_pub, msg).expect("dm");
    assert_eq!(
        open_message_from_user(&bob_sec.sealing, &a_pub.signing, &dm).as_deref(),
        Ok(msg.as_ref())
    );
}

/// A user's subkeys in multiple cells validate one another (shared master).
#[test]
fn user_subkeys_across_cells_validate_one_another() {
    let (master_pub, master_sec) = principal_from_seed(&seed("alice-master")).expect("master");
    let (sub_a, _) = principal_from_seed(&seed("alice@cellA")).expect("subA");
    let (sub_b, _) = principal_from_seed(&seed("alice@cellB")).expect("subB");
    let cell_a = CellId::from_bytes(b"cell-A".to_vec());
    let cell_b = CellId::from_bytes(b"cell-B".to_vec());

    let cert_a = certify_subkey(&master_sec.signing, &sub_a, &cell_a).expect("cert A");
    let cert_b = certify_subkey(&master_sec.signing, &sub_b, &cell_b).expect("cert B");

    // Both subkeys chain to the same master -> proven the same user across cells.
    assert_eq!(
        verify_subkey(&master_pub.signing, &sub_a, &cell_a, &cert_a),
        Ok(())
    );
    assert_eq!(
        verify_subkey(&master_pub.signing, &sub_b, &cell_b, &cert_b),
        Ok(())
    );
}

/// Cell-to-cell messaging: a cell is a principal, so cell A seals to cell B.
#[test]
fn cell_to_cell_messaging() {
    let (_cell_a_pub, _cell_a_sec) = principal_from_seed(&seed("cell-A")).expect("cell A");
    let (cell_b_pub, cell_b_sec) = principal_from_seed(&seed("cell-B")).expect("cell B");

    let msg = b"cell-A -> cell-B: cross-cell access grant for alice";
    let sealed = seal_to_recipients(msg, &[cell_b_pub.sealing]).expect("seal to cell B");
    assert_eq!(
        unseal(&sealed, &cell_b_sec.sealing).as_deref(),
        Ok(msg.as_ref())
    );
}

/// User-to-user across cells: sealing is independent of cell membership.
#[test]
fn user_to_user_in_another_cell() {
    let (_alice_pub, alice_sec) = principal_from_seed(&seed("alice@cellA")).expect("alice");
    let (alice_pub, _) = principal_from_seed(&seed("alice@cellA")).expect("alice pub");
    let (bob_pub, bob_sec) = principal_from_seed(&seed("bob@cellB")).expect("bob in another cell");

    let msg = b"alice(cellA) -> bob(cellB): here is the artifact CID";
    let dm = seal_message_to_user(&alice_sec.signing, &bob_pub, msg).expect("cross-cell dm");
    assert_eq!(
        open_message_from_user(&bob_sec.sealing, &alice_pub.signing, &dm).as_deref(),
        Ok(msg.as_ref()),
        "bob in another cell opens it and verifies alice"
    );
}
