/*
This is a wrapper implementation for Pebble on top of bls-eth-rust library.
 */

use bls_eth_rust::*;
use hex;

// Creates a new cryptographically secure secret key
pub fn rand_secretkey() -> SecretKey {
    let mut key = unsafe { SecretKey::uninit() };
    key.set_by_csprng();
    return key;
}

// Deserializes the secret key from it's bytes
pub fn secretkey_from_bytes(bytes: &str) -> SecretKey {
    SecretKey::from_serialized(&hex::decode(bytes).unwrap()).unwrap()
}
// Deserializes the public key from it's bytes
pub fn publickey_from_bytes(bytes: &str) -> PublicKey {
    PublicKey::from_serialized(&hex::decode(bytes).unwrap()).unwrap()
}
// Deserializes the signature key from it's bytes
pub fn signature_from_bytes(bytes: &str) -> Signature {
    Signature::from_serialized(&hex::decode(bytes).unwrap()).unwrap()
}
// Aggregates a vector of signatures to a single signature
pub fn aggregate_signatures(sigs: Vec<Signature>) -> Signature {
    let mut agg = unsafe { Signature::uninit() };
    agg.aggregate(&sigs);
    agg
}
// Returns true if the given vector of messages, signatures and publickeys are correct
// else None is returned
pub fn verify_multiple_signatures(msgs: Vec<u8>, sigs: Vec<Signature>,
                                  pubkeys: Vec<PublicKey>) -> Option<bool> {
    return if are_all_msg_different(&msgs, MSG_SIZE) {
        let mut agg_sig = unsafe { Signature::uninit() };
        agg_sig.aggregate(&sigs);
        Some(agg_sig.aggregate_verify_no_check(&pubkeys, &msgs))
    } else {
        println!(" Messages are not different, this fn expects the messages to be different.");
        None
    };
}
// Returns a blank signature
pub fn create_blank_signature() -> Signature {
    let sig = unsafe { Signature::uninit() };
    sig
}

#[cfg(test)]
mod tests {
    use crate::{rand_secretkey,
                secretkey_from_bytes,
                publickey_from_bytes};

    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }

    #[test]
    fn rand_secretkey_generation() {
        let key = rand_secretkey();
        let hexkey = hex::encode(key.get_publickey().as_bytes());
        // println!("Secret Key: {}",hex::encode(key.serialize()));
        // println!("The Public Key: {}",hexkey);
        assert_eq!(hexkey.len(), 96)
    }

    #[test]
    fn test_secretkey_from_bytes() {
        let key1 = rand_secretkey();
        let secretkey_bytes = hex::encode(key1.serialize());
        let key2 = secretkey_from_bytes(&secretkey_bytes);
        assert_eq!(key1, key2);
    }

    #[test]
    fn test_publickey_from_bytes() {
        let key = rand_secretkey();
        let pubkeyhex1 = hex::encode(key.get_publickey().as_bytes());
        let pubkey2 = publickey_from_bytes(&pubkeyhex1);
        assert_eq!(pubkey2, key.get_publickey())
    }

    #[test]
    fn test_signing_verifying(){
        let key = rand_secretkey();
        let msg_hex = "5656565656565656565656565656565656565656565656565656565656565656";
        let msg = hex::decode(&msg_hex).unwrap();
        let pubkey = key.get_publickey();
        let sig = key.sign(&msg);
        assert!(sig.verify(&pubkey, &msg));
        assert_eq!(msg.len(),32);
    }
}
