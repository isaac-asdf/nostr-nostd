use core::str::FromStr;

use heapless::{String, Vec};
use secp256k1::{ecdh, PublicKey, SecretKey, XOnlyPublicKey};

// use aes::cipher::block_padding::Pkcs7;
use aes::cipher::{BlockDecryptMut, BlockEncryptMut, KeyIvInit};
use aes::{Aes256, Block};
use cbc::{Decryptor, Encryptor};

type Aes256CbcEnc = Encryptor<Aes256>;
type Aes256CbcDec = Decryptor<Aes256>;

use crate::errors::Error;
use crate::NOTE_SIZE;

/// heavily copied from rust-nostr
///

/// Entrypt
pub fn encrypt<T>(sk: &SecretKey, pk: &XOnlyPublicKey, text: T) -> Result<String<NOTE_SIZE>, Error>
where
    T: AsRef<[u8]>,
{
    let key: [u8; 32] = generate_shared_key(sk, pk)?;
    // let iv: [u8; 16] = secp256k1::rand::Rng();
    let iv: [u8; 16] = [0; 16];

    let cipher = Aes256CbcEnc::new(&key.into(), &iv.into());
    // let mut blocks: Block = text.into();
    // cipher.encrypt_blocks_mut(blocks);

    // Ok(format!(
    //     "{}?iv={}",
    //     general_purpose::STANDARD.encode(result),
    //     general_purpose::STANDARD.encode(iv)
    // ))
    Ok(String::new())
}

// /// Dectypt
// pub fn decrypt<S>(
//     sk: &SecretKey,
//     pk: &XOnlyPublicKey,
//     encrypted_content: S,
// ) -> Result<String, Error>
// where
//     S: Into<String>,
// {
//     let encrypted_content: String = encrypted_content.into();
//     let parsed_content: Vec<&str, 2> = encrypted_content.split("?iv=").collect();
//     if parsed_content.len() != 2 {
//         return Err(Error::InvalidContentFormat);
//     }

//     let encrypted_content: Vec<u8> = general_purpose::STANDARD
//         .decode(parsed_content[0])
//         .map_err(|_| Error::Base64Decode)?;
//     let iv: Vec<u8> = general_purpose::STANDARD
//         .decode(parsed_content[1])
//         .map_err(|_| Error::Base64Decode)?;
//     let key: [u8; 32] = generate_shared_key(sk, pk)?;

//     let cipher = Aes256CbcDec::new(&key.into(), iv.as_slice().into());
//     let result = cipher
//         .decrypt_padded_vec_mut::<Pkcs7>(&encrypted_content)
//         .map_err(|_| Error::WrongBlockMode)?;

//     String::from_utf8(result).map_err(|_| Error::Utf8Encode)
// }

/// Generate shared key
fn generate_shared_key(sk: &SecretKey, pk: &XOnlyPublicKey) -> Result<[u8; 32], Error> {
    let pk_normalized: PublicKey = normalize_schnorr_pk(pk)?;
    let ssp = ecdh::shared_secret_point(&pk_normalized, sk);
    let mut shared_key: [u8; 32] = [0u8; 32];
    shared_key.copy_from_slice(&ssp[..32]);
    Ok(shared_key)
}

/// Normalize Schnorr public key
fn normalize_schnorr_pk(schnorr_pk: &XOnlyPublicKey) -> Result<PublicKey, Error> {
    let mut pk: String<66> = String::from("02");
    let mut bytes = [0_u8; 64];
    base16ct::lower::encode(&schnorr_pk.serialize(), &mut bytes)
        .map_err(|_| Error::InternalPubkeyError)?;
    // pk.push_str(&schnor_key).map_err(|_| Error::InternalError)?;
    bytes.iter().try_for_each(|b| {
        let c = char::from_u32(*b as u32).ok_or(Error::InternalError)?;
        pk.push(c).map_err(|_| Error::InternalError)?;
        Ok(())
    })?;
    Ok(PublicKey::from_str(&pk).map_err(|_| Error::InternalPubkeyError)?)
}

#[cfg(test)]
mod tests {
    use secp256k1::{ffi::types::AlignedType, KeyPair};

    use super::*;
    const DM_RECV: &str = r#"{"content":"sZhES/uuV1uMmt9neb6OQw6mykdLYerAnTN+LodleSI=?iv=eM0mGFqFhxmmMwE4YPsQMQ==","created_at":1691110186,"id":"517a5f0f29f5037d763bbd5fbe96c9082c1d39eca917aa22b514c5effc36bab9","kind":4,"pubkey":"ed984a5438492bdc75860aad15a59f8e2f858792824d615401fb49d79c2087b0","sig":"3097de7d5070b892b81b245a5b276eccd7cb283a29a934a71af4960188e55e87d639b774cc331eb9f94ea7c46373c52b8ab39bfee75fe4bb11a1dd4c187e1f3e","tags":[["p","098ef66bce60dd4cf10b4ae5949d1ec6dd777ddeb4bc49b47f97275a127a63cf"]]}"#;
    const DM_SEND: &str = r#"{"content":"lPQ9iBd6abUrDBJbHWaL3qqhqsuAxK0aU80IgsZ2aqE=?iv=O1zZfD9HPiig1yuZEWX7uQ==","created_at":1691117390,"id":"c0be8c32d95f7599ccfe324711ad50890ee08985710997fcda1a1a3840a23d51","kind":4,"pubkey":"098ef66bce60dd4cf10b4ae5949d1ec6dd777ddeb4bc49b47f97275a127a63cf","sig":"8ee1e83ab037c9e9ff1ac97db88aa045b2f1d9204daa7fee25e5f42274ee8d5f4365b87677c4f27827ca043becc65c1f38f646d05adf3d2c570b66fea57e5918","tags":[["p","ed984a5438492bdc75860aad15a59f8e2f858792824d615401fb49d79c2087b0"]]}"#;
    const FROM_SKEY: &str = "aecb67d55da9b658cd419013d7026f30ee23c5c5b032948e84e8ae523b559f92";
    const MY_SKEY: &str = "a5084b35a58e3e1a26f5efb46cb9dbada73191526aa6d11bccb590cbeb2d8fa3";
    const EXPCTD_MSG: &str = "hello from the internet";

    #[test]
    fn test_encrypt() {
        let mut buf = [AlignedType::zeroed(); 64];
        let sig_obj = secp256k1::Secp256k1::preallocated_new(&mut buf).unwrap();
        let key_pair = KeyPair::from_seckey_str(&sig_obj, FROM_SKEY).unwrap();
        let pk = key_pair.x_only_public_key().0;

        let my_sk = SecretKey::from_str(MY_SKEY).unwrap();
        let encrypted = encrypt(&my_sk, &pk, EXPCTD_MSG).expect("test");
        assert_eq!(
            encrypted.as_str(),
            "lPQ9iBd6abUrDBJbHWaL3qqhqsuAxK0aU80IgsZ2aqE=?iv=O1zZfD9HPiig1yuZEWX7uQ=="
        );
    }
}