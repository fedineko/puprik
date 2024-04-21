use std::fs;
use base64::Engine;
use base64::prelude::BASE64_STANDARD;
use hmac::Hmac;
use rsa::RsaPrivateKey;
use rsa::pkcs1::DecodeRsaPrivateKey;
use rsa::pkcs8::DecodePrivateKey;
use rsa::signature::{RandomizedSigner, SignatureEncoding, Signer};
use rsa::signature::digest::Mac;
use rsa::sha2::{Sha256, Sha512};
use log::{debug, error};


/// Internally used wrapper for different types of signing keys.
enum InnerCryptoSigner {
    // Need to support all of these:
    // https://www.rfc-editor.org/rfc/rfc9421.html#name-initial-contents

    // - rsa-pss-sha512  : RSASSA-PSS using SHA-512
    RsaPssSha512(Box<rsa::pss::SigningKey<Sha512>>),

    // - rsa-v1_5-sha256 : RSASSA-PKCS1-v1_5 using SHA-256
    RsaPkcs1v15Sha256(Box<rsa::pkcs1v15::SigningKey<Sha256>>),

    // - ed25519 : EdDSA using curve edwards25519
    ED25519(Box<dyn Signer<ed25519::Signature>>),

    // hmac-sha256 : HMAC using SHA-256
    HmacSha256(Vec<u8>),

    // - ecdsa-p256-sha256 : ECDSA using curve P-256 DSS and SHA-256
    EcdsaP256Sha256(Box<dyn Signer<p256::ecdsa::Signature>>),

    // - ecdsa-p384-sha384 : ECDSA using curve P-384 DSS and SHA-384
}


/// Represents private key of some sort, hiding all specific algorithm
/// related or crypto implementation details under the hood.
pub struct PrivateKey {
    /// Key identifier, is not used for signing directly.
    id: String,
    /// Key algorithm, such as 'ed25519'.
    sign_algorithm: &'static str,
    /// Actual signer used by this key object.
    inner_crypto: InnerCryptoSigner,
}


impl PrivateKey {
    /// Returns ID of the key.
    pub fn key_id(&self) -> &str {
        self.id.as_str()
    }

    /// Returns algorithm of the key.
    pub fn key_alg(&self) -> &str {
        self.sign_algorithm
    }

    /// Attempts to construct private RSA key with `key_id` identifier from
    /// `text` material set in PEM format. Both PKCS#1 and PKCS#8 are attempted
    /// before giving up.
    fn rsa_private_key_from_text(
        key_id: &str,
        text: &str,
    ) -> Option<RsaPrivateKey> {
        let key = RsaPrivateKey::from_pkcs8_pem(text);

        if let Ok(ok_key) = key {
            return Some(ok_key);
        }

        debug!(
            "Failed to read {key_id} as PKCS#8, trying PKCS#1 instead: {:?}",
            key.err().unwrap()
        );

        let key = RsaPrivateKey::from_pkcs1_pem(text);

        if let Ok(ok_key) = key {
            return Some(ok_key);
        }

        error!(
            "Failed to read private {key_id} as PKCS#1 as well: {:?}",
            key.err().unwrap()
        );

        None
    }

    /// Attempts to construct private RSA key with `key_id` identifier from
    /// `text` material set in PEM format assuming it is PKCS#1 v1.5.
    fn try_rsa_pkcs_v15_sha256(key_id: &str, text: &str) -> Option<Self> {
        Self::rsa_private_key_from_text(key_id, text)
            .map(|rsa_key| {
                Self {
                    id: key_id.to_string(),
                    inner_crypto: InnerCryptoSigner::RsaPkcs1v15Sha256(
                        Box::new(rsa::pkcs1v15::SigningKey::new(rsa_key))
                    ),
                    sign_algorithm: "rsa-v1_5-sha256",
                }
            })
    }

    /// Attempts to construct private RSA key with `key_id` identifier from
    /// `text` material set in PEM format assuming that it is PSS key.
    fn try_rsa_pss_sha512(key_id: &str, text: &str) -> Option<Self> {
        Self::rsa_private_key_from_text(key_id, text)
            .map(|rsa_key| {
                Self {
                    id: key_id.to_string(),
                    inner_crypto: InnerCryptoSigner::RsaPssSha512(
                        Box::new(rsa::pss::SigningKey::new(rsa_key))
                    ),
                    sign_algorithm: "rsa-pss-sha512",
                }
            })
    }

    /// Attempts to construct private ED25519 key with `key_id` identifier from
    /// `text` material set in PEM format.
    fn try_ed25519(key_id: &str, text: &str) -> Option<Self> {
        match ed25519_dalek::SigningKey::from_pkcs8_pem(text) {
            Ok(key) => Some(
                Self {
                    id: key_id.to_string(),
                    inner_crypto: InnerCryptoSigner::ED25519(Box::new(key)),
                    sign_algorithm: "ed25519",
                }
            ),

            Err(err) => {
                error!("Failed to read ED25519 {key_id}: {err:?}");
                None
            }
        }
    }

    /// Attempts to construct private ECDSA key with `key_id` identifier from
    /// `text` material set in PEM format.
    fn try_ecdsa_p256_sha256(key_id: &str, text: &str) -> Option<Self> {
        match ecdsa::SigningKey::from_pkcs8_pem(text) {
            Ok(key) => Some(
                Self {
                    id: key_id.to_string(),
                    inner_crypto: InnerCryptoSigner::EcdsaP256Sha256(
                        Box::new(key)
                    ),
                    sign_algorithm: "ecdsa-p256-sha256",
                }
            ),

            Err(err) => {
                println!("{:?}", err);
                error!("Failed to read ECDSA {key_id}: {err:?}");
                None
            }
        }
    }

    /// Attempts to construct HMAC key with `key_id` identifier from
    /// `text` material set in base64 format.
    fn try_hmac_sha256(key_id: &str, text: &str) -> Option<Self> {
        let key_bytes = match BASE64_STANDARD.decode(text) {
            Ok(bytes) => bytes,

            Err(err) => {
                error!("Could not decode HMAC base64: {err:?}, text: {text}");
                return None;
            }
        };

        Some(
            Self {
                id: key_id.to_string(),
                inner_crypto: InnerCryptoSigner::HmacSha256(key_bytes),
                sign_algorithm: "hmac-sha256",
            }
        )
    }

    /// Attempts to construct private key with `key_id` identifier from
    /// `text` material set.
    ///
    /// If `hint` is specified attempts to load key assuming it is key
    /// matching hinted algorithm. Otherwise, tries all known algorithms
    /// one by one until any succeeds.
    pub fn from_pem_text(
        key_id: &str,
        text: &str,
        hint: Option<&str>,
    ) -> Option<Self> {
        if let Some(hint) = hint {
            match hint {
                "rsa" |
                "rsa-sha256" |
                "rsa-v1_5-sha256" => return Self::try_rsa_pkcs_v15_sha256(
                    key_id, text,
                ),

                "rsa-pss-sha512" => return Self::try_rsa_pss_sha512(
                    key_id, text,
                ),

                "ed25519" => return Self::try_ed25519(key_id, text),

                "hmac-sha256" => return Self::try_hmac_sha256(key_id, text),

                "ecdsa-p256-sha256" => return Self::try_ecdsa_p256_sha256(
                    key_id, text,
                ),

                _ => {}
            }
        }

        // try one by one
        Self::try_rsa_pkcs_v15_sha256(key_id, text)
            .or_else(|| Self::try_ed25519(key_id, text))
            .or_else(|| Self::try_rsa_pss_sha512(key_id, text))
            .or_else(|| Self::try_ecdsa_p256_sha256(key_id, text))
            .or_else(|| Self::try_hmac_sha256(key_id, text))
    }

    /// Attempts to load private RSA key with `key_id` identifier from
    /// PEM file specified in `key_path`.
    ///
    /// TODO: deprecate and remove.
    pub fn rsa_key_from_file_path(
        key_path: &str,
        key_id: &str,
    ) -> Option<Self> {
        let key_text = fs::read_to_string(key_path).unwrap();

        PrivateKey::from_pem_text(
            key_id,
            &key_text,
            Some("rsa"),
        )
    }

    /// Helper method to produce HMAC SHA256 for `message` and shared `secret`.
    fn sign_hmac_sha256(
        &self,
        message: &[u8],
        secret: &[u8],
    ) -> Option<Vec<u8>> {
        let mut hmac = match Hmac::<Sha256>::new_from_slice(secret) {
            Ok(value) => value,

            Err(err) => {
                error!("Failed to sign with HMAC SHA256: {err:?}");
                return None;
            }
        };

        hmac.update(message);

        let result = hmac.finalize();
        let bytes = result.into_bytes();

        Some(
            Vec::from(&bytes[..])
        )
    }

    /// Signs `message` message using private key and returns result as u8 vector.
    pub fn sign(&self, message: &[u8]) -> Option<Vec<u8>> {
        match &self.inner_crypto {
            InnerCryptoSigner::ED25519(signer) => {
                let signature = signer.sign(message);
                Some(signature.to_vec())
            }

            InnerCryptoSigner::RsaPkcs1v15Sha256(signing_key) => {
                let signature = signing_key.sign(message);
                Some(signature.to_vec())
            }

            InnerCryptoSigner::RsaPssSha512(signing_key) => {
                let mut rng = rand::thread_rng();
                let signature = signing_key.sign_with_rng(&mut rng, message);
                Some(signature.to_vec())
            }

            InnerCryptoSigner::HmacSha256(secret) => {
                self.sign_hmac_sha256(message, secret)
            }

            InnerCryptoSigner::EcdsaP256Sha256(signing_key) => {
                let signature = signing_key.sign(message);
                Some(signature.to_vec())
            }
        }
    }

    /// Signs `text` message using private key and returns result encoded as base64
    pub fn sign_as_base64(&self, text: &str) -> Option<String> {
        let bytes = text.as_bytes();

        self.sign(bytes)
            .map(|bytes| BASE64_STANDARD.encode(bytes))
    }
}

#[cfg(test)]
mod test {
    use crate::private_key::PrivateKey;

    // PSS keys signing works in `rsa` crate since
    // https://github.com/RustCrypto/RSA/commit/e54fb7da1a7dea1602bdb7da8e9fbbca9edc4060
    // This test should be enabled when it is stabilized in mainline.
    // #[test]
    fn test_b21_rsa_pss_sha512() {
        const PRIVATE_KEY_TEXT: &str = include_str!("test_data/test-key-rsa-pss-priv.pem");
        const EXPECTED_SIGNATURE: &str = include_str!("test_data/b21_signature");
        const MESSAGE: &str = include_str!("test_data/b21_message");

        let private_key = PrivateKey::from_pem_text(
            "test-key-rsa-pss",
            PRIVATE_KEY_TEXT,
            Some("rsa-pss-sha512"),
        ).unwrap();

        let signature = private_key.sign_as_base64(MESSAGE).unwrap();

        assert_eq!(EXPECTED_SIGNATURE, signature);
    }

    // This one fails to read key citing Asn1 error:
    // TagUnexpected {
    //     expected: Some(Tag(0x30: SEQUENCE)),
    //     actual: Tag(0x04: OCTET STRING) },
    //     position: Some(Length(5))
    // }
    // Needs further investigation.
    // #[test]
    fn test_b24_ecc_p256() {
        const PRIVATE_KEY_TEXT: &str = include_str!("test_data/test-key-ecc-p256-priv.pem");
        const SIGNATURE_BASE: &str = include_str!("test_data/b24_signature_base");
        const EXPECTED_SIGNATURE: &str = include_str!("test_data/b24_signature");

        let private_key = PrivateKey::from_pem_text(
            "test-key-ecc-p256",
            PRIVATE_KEY_TEXT,
            Some("ecdsa-p256-sha256"),
        ).unwrap();

        let signature = private_key.sign_as_base64(SIGNATURE_BASE).unwrap();

        assert_eq!(EXPECTED_SIGNATURE, signature);
    }

    #[test]
    fn test_b26_ed25519() {
        const PRIVATE_KEY_TEXT: &str = include_str!("test_data/test-key-ed25519-priv.pem");
        const SIGNATURE_BASE: &str = include_str!("test_data/b26_signature_base");
        const EXPECTED_SIGNATURE: &str = include_str!("test_data/b26_signature");

        let private_key = PrivateKey::from_pem_text(
            "test-key-ed25519",
            PRIVATE_KEY_TEXT,
            Some("ed25519"),
        ).unwrap();

        let signature = private_key.sign_as_base64(SIGNATURE_BASE).unwrap();

        assert_eq!(EXPECTED_SIGNATURE, signature);
    }
}

