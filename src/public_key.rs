use base64::Engine;
use base64::prelude::BASE64_STANDARD;
use hmac::{Hmac, Mac};
use log::{debug, error, info, warn};
use rsa::pkcs1::DecodeRsaPublicKey;
use rsa::pkcs8::DecodePublicKey;
use rsa::RsaPublicKey;
use rsa::sha2::{Sha256, Sha512};
use rsa::signature::Verifier;

/// Internally used wrapper for different types of supported keys.
#[derive(Clone)]
pub enum InnerCryptoVerifier {
    // Need to support all of these:
    // https://www.rfc-editor.org/rfc/rfc9421.html#name-initial-contents

    // - ed25519 : EdDSA using curve edwards25519
    ED25519(ed25519_dalek::VerifyingKey),

    // rsa-v1_5-sha256 : RSASSA-PKCS1-v1_5 using SHA-256
    RsaPkcs1v15(rsa::pkcs1v15::VerifyingKey<Sha256>),

    // rsa-pss-sha512  : RSASSA-PSS using SHA-512
    RsaPssSha512(rsa::pss::VerifyingKey<Sha512>),

    // hmac-sha256 : HMAC using SHA-256
    HmacSha256(Vec<u8>),

    // ecdsa-p256-sha256 : ECDSA using curve P-256 DSS and SHA-256
    EcdsaP256Sha256(p256::ecdsa::VerifyingKey),

    // - ecdsa-p384-sha384 : ECDSA using curve P-384 DSS and SHA-384
}

/// Public key wrapper that hides key and crypto engine details
/// under the hood.
#[derive(Clone)]
pub struct PublicKey {
    /// Key identifier used to identify shared public key.
    id: String,
    /// Actual key used to verify signatures.
    inner_crypto: InnerCryptoVerifier,
    /// Key algorithm such as 'hmac-sha256'
    algorithm: &'static str,
}

impl PublicKey {
    /// Returns key identifier.
    pub fn key_id(&self) -> &str {
        self.id.as_str()
    }

    /// Returns key algorithm.
    pub fn key_alg(&self) -> &str {
        self.algorithm
    }

    /// Attempts to construct public RSA key with `key_id` identifier from
    /// `text` material set in PEM format. Both PKCS#1 and PKCS#8 are attempted
    /// before giving up.
    fn rsa_public_key_from_text(
        key_id: &str,
        text: &str
    ) -> Option<RsaPublicKey> {
        let key = RsaPublicKey::from_public_key_pem(text);

        if let Ok(ok_key) = key {
            return Some(ok_key);
        }

        debug!(
            "Failed to read public RSA {key_id} as PKCS#8, \
            trying PKCS#1 instead: {:?}",
            key.err().unwrap()
        );

        let key = RsaPublicKey::from_pkcs1_pem(text);

        if let Ok(ok_key) = key {
            return Some(ok_key);
        }

        error!(
            "Failed to read public RSA {key_id} as PKCS#1 or PKCS#8: {:?}, \
            PEM text is '{text}'",
            key.err().unwrap()
        );

        None
    }

    /// Attempts to construct public RSA key with `key_id` identifier from
    /// `text` material set in PEM format assuming it is PKCS#1 v1.5.
    fn try_rsa_pkcs_v15_sha256(key_id: &str, text: &str) -> Option<Self> {
        Self::rsa_public_key_from_text(key_id, text)
            .map(|rsa_key| Self {
                id: key_id.to_string(),
                inner_crypto: InnerCryptoVerifier::RsaPkcs1v15(
                    rsa::pkcs1v15::VerifyingKey::new(rsa_key)
                ),
                algorithm: "rsa-v1_5-sha256",
            })
    }

    /// Attempts to construct public RSA key with `key_id` identifier from
    /// `text` material set in PEM format assuming it is counterpart for PSS key.
    fn try_rsa_pss_sha512(key_id: &str, text: &str) -> Option<Self> {
        Self::rsa_public_key_from_text(key_id, text)
            .map(|rsa_key| Self {
                id: key_id.to_string(),
                inner_crypto: InnerCryptoVerifier::RsaPssSha512(
                    rsa::pss::VerifyingKey::new(rsa_key)
                ),
                algorithm: "rsa-pss-sha512",
            })
    }

    /// Attempts to construct public ED25519 key with `key_id` identifier from
    /// `text` material set in PEM format.
    fn try_ed25519(key_id: &str, text: &str) -> Option<Self> {
        match ed25519_dalek::VerifyingKey::from_public_key_pem(text) {
            Ok(key) => Some(
                Self {
                    id: key_id.to_string(),
                    inner_crypto: InnerCryptoVerifier::ED25519(key),
                    algorithm: "ed25519",
                }
            ),

            Err(err) => {
                error!(
                    "Failed to read ED25519 {key_id}: {err:?}, \
                    PEM text is '{text}'"
                );

                None
            }
        }
    }

    /// Attempts to construct private ECDSA key with `key_id` identifier from
    /// `text` material set in PEM format.
    fn try_ecdsa_p256_sha256(key_id: &str, text: &str) -> Option<Self> {
        match ecdsa::VerifyingKey::from_public_key_pem(text) {
            Ok(key) => Some(
                Self {
                    id: key_id.to_string(),
                    inner_crypto: InnerCryptoVerifier::EcdsaP256Sha256(key),
                    algorithm: "ecdsa-p256-sha256",
                }
            ),

            Err(err) => {
                error!(
                    "Failed to read ECDSA P256 {key_id}: {err:?}, \
                    PEM text is '{text}'"
                );

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
                error!("Could not decode HMAC base64: {err:?}");
                return None;
            }
        };

        Some(
            Self {
                id: key_id.to_string(),
                inner_crypto: InnerCryptoVerifier::HmacSha256(key_bytes),
                algorithm: "hmac-sha256",
            }
        )
    }

    /// Attempts to construct public key with `key_id` identifier from
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
        let trimmy_text = text.trim();
        let hint = hint.unwrap_or("<no-hint>");

        info!("Reading key {key_id} with hint '{hint}'");

        match hint {
            "rsa" |
            "rsa-v1_5-sha256" |
            "rsa-sha256" => return Self::try_rsa_pkcs_v15_sha256(
                key_id, trimmy_text,
            ),

            "rsa-pss-sha512" => return Self::try_rsa_pss_sha512(
                key_id, trimmy_text,
            ),

            "ed25519" => return Self::try_ed25519(
                key_id, trimmy_text,
            ),

            "hmac-sha256" => return Self::try_hmac_sha256(
                key_id, trimmy_text,
            ),

            "ecdsa-p256-sha256" => return Self::try_ecdsa_p256_sha256(
                key_id, trimmy_text,
            ),

            _ => {
                info!(
                    "No applicable hint for key {key_id}, \
                    will probe all options one by one"
                );
            }
        }

        // try one by one
        Self::try_rsa_pkcs_v15_sha256(key_id, trimmy_text)
            .or_else(|| Self::try_ed25519(key_id, trimmy_text))
            .or_else(|| Self::try_rsa_pss_sha512(key_id, trimmy_text))
            .or_else(|| Self::try_ecdsa_p256_sha256(key_id, trimmy_text))
            .or_else(|| Self::try_hmac_sha256(key_id, trimmy_text))
    }

    /// Helper method to verify ED25519 `signature_bytes` for `message_bytes`
    /// with `verifier` key.
    fn verify_ed25519(
        &self,
        verifier: &ed25519_dalek::VerifyingKey,
        message_bytes: &[u8],
        signature_bytes: &[u8],
    ) -> bool {
        let signature = match ed25519::Signature::from_slice(signature_bytes) {
            Ok(signature) => {
                signature
            }

            Err(err) => {
                warn!("Failed to read signature as ed25519: {err:?}");
                return false;
            }
        };

        match verifier.verify(message_bytes, &signature) {
            Ok(_) => true,

            Err(err) => {
                info!("Signature verification failed: {err:?}");
                false
            }
        }
    }

    /// Helper method to verify ECDSA `signature_bytes` for `message_bytes`
    /// with `verifier` key.
    fn verify_ecdsa_p256_sha256(
        &self,
        verifier: &p256::ecdsa::VerifyingKey,
        message_bytes: &[u8],
        signature_bytes: &[u8],
    ) -> bool {
        let signature = match ecdsa::Signature::from_slice(signature_bytes) {
            Ok(signature) => {
                signature
            }

            Err(err) => {
                warn!(
                    "Failed to read signature as ecdsa-p256-sha256: {err:?}"
                );

                return false;
            }
        };

        match verifier.verify(message_bytes, &signature) {
            Ok(_) => true,

            Err(err) => {
                info!("Signature verification failed: {err:?}");
                false
            }
        }
    }

    /// Helper method to verify RSA `signature_bytes` for `message_bytes`
    /// with `verifier` key.
    fn verify_rsa_pkcs_v15_sha256(
        &self,
        verifier: &rsa::pkcs1v15::VerifyingKey<Sha256>,
        message_bytes: &[u8],
        signature_bytes: &[u8],
    ) -> bool {
        let signature = match rsa::pkcs1v15::Signature::try_from(
            signature_bytes
        ) {
            Ok(signature) => {
                signature
            }

            Err(err) => {
                warn!("Failed to read signature as RSA: PKCS v1.5 {err:?}");
                return false;
            }
        };

        match verifier.verify(message_bytes, &signature) {
            Ok(_) => true,

            Err(err) => {
                info!("Signature verification failed: {err:?}");
                false
            }
        }
    }

    /// Helper method to verify RSA PSS `signature_bytes` for `message_bytes`
    /// with `verifier` key.
    fn verify_rsa_pss_sha512(
        &self,
        verifier: &rsa::pss::VerifyingKey<Sha512>,
        message_bytes: &[u8],
        signature_bytes: &[u8],
    ) -> bool {
        let signature = match rsa::pss::Signature::try_from(signature_bytes) {
            Ok(signature) => {
                signature
            }

            Err(err) => {
                warn!("Failed to read signature as RSA PSS: {err:?}");
                return false;
            }
        };

        match verifier.verify(message_bytes, &signature) {
            Ok(_) => true,

            Err(err) => {
                info!("Signature verification failed: {err:?}");
                false
            }
        }
    }

    /// Helper method to verify HMAC `signature_bytes` for `message_bytes`
    /// with shared `key`.
    fn verify_hmac_sha256(
        &self,
        key: &[u8],
        message_bytes: &[u8],
        signature_bytes: &[u8],
    ) -> bool {
        match Hmac::<Sha256>::new_from_slice(key) {
            Ok(mut verifier) => {
                verifier.update(message_bytes);

                match verifier.verify_slice(signature_bytes) {
                    Ok(_) => true,

                    Err(err) => {
                        info!("Signature verification failed: {err:?}");
                        false
                    }
                }
            }

            Err(err) => {
                error!(
                    "Failed to read HMAC: {err:?}, text is '{message_bytes:?}'"
                );

                false
            }
        }
    }

    /// Verify `message_bytes` using public key and `signature_bytes`,
    /// returns true if signature matches.
    pub fn verify(&self, message_bytes: &[u8], signature_bytes: &[u8]) -> bool {
        match &self.inner_crypto {
            InnerCryptoVerifier::ED25519(verifier) => {
                self.verify_ed25519(verifier, message_bytes, signature_bytes)
            }

            InnerCryptoVerifier::RsaPkcs1v15(verifying_key) => {
                self.verify_rsa_pkcs_v15_sha256(
                    verifying_key, message_bytes, signature_bytes,
                )
            }

            InnerCryptoVerifier::HmacSha256(secret) => {
                self.verify_hmac_sha256(secret, message_bytes, signature_bytes)
            }

            InnerCryptoVerifier::RsaPssSha512(verifying_key) => {
                self.verify_rsa_pss_sha512(
                    verifying_key, message_bytes, signature_bytes,
                )
            }

            InnerCryptoVerifier::EcdsaP256Sha256(verifier) => {
                self.verify_ecdsa_p256_sha256(
                    verifier, message_bytes, signature_bytes,
                )
            }
        }
    }

    /// Verify `message` message string using public key and `signature`
    /// string, returns boolean result.
    pub fn verify_base64(&self, message: &str, signature: &str) -> bool {
        let signature_bytes = match BASE64_STANDARD.decode(signature) {
            Ok(bytes) => bytes,

            Err(err) => {
                info!("Filed to decode base64 signature {signature}: {err:?}");
                return false;
            }
        };

        self.verify(message.as_bytes(), &signature_bytes)
    }
}

#[cfg(test)]
mod tests {
    use crate::public_key::PublicKey;

    #[test]
    fn test_b25_hmac_sha256() {
        const SIGNATURE_BASE: &str = include_str!("test_data/b25_signature_base");
        const SHARED_SECRET: &str = include_str!("test_data/b25_shared_secret");
        const SIGNATURE: &str = include_str!("test_data/b25_signature");

        let key = PublicKey::from_pem_text(
            "test-shared-secret",
            SHARED_SECRET,
            Some("hmac-sha256"),
        ).unwrap();

        assert!(key.verify_base64(SIGNATURE_BASE, SIGNATURE));
    }

    #[test]
    fn test_b21_rsa_pss() {
        const PUBLIC_KEY_TEXT: &str = include_str!("test_data/test-key-rsa-pss.pem");
        const SIGNATURE_BASE: &str = include_str!("test_data/b21_signature_base");
        const SIGNATURE: &str = include_str!("test_data/b21_signature");

        let public_key = PublicKey::from_pem_text(
            "test-key-rsa-pss",
            PUBLIC_KEY_TEXT,
            Some("rsa-pss-sha512"),
        ).unwrap();

        assert!(public_key.verify_base64(SIGNATURE_BASE, SIGNATURE));
    }

    #[test]
    fn test_b24_ecc_p256() {
        const PUBLIC_KEY_TEXT: &str = include_str!("test_data/test-key-ecc-p256.pem");
        const SIGNATURE_BASE: &str = include_str!("test_data/b24_signature_base");
        const SIGNATURE: &str = include_str!("test_data/b24_signature");

        let public_key = PublicKey::from_pem_text(
            "test-key-ecc-p256",
            PUBLIC_KEY_TEXT,
            Some("ecdsa-p256-sha256"),
        ).unwrap();

        assert!(public_key.verify_base64(SIGNATURE_BASE, SIGNATURE));
    }

    #[test]
    fn test_b26_ed25519() {
        const PUBLIC_KEY_TEXT: &str = include_str!("test_data/test-key-ed25519.pem");
        const SIGNATURE_BASE: &str = include_str!("test_data/b26_signature_base");
        const SIGNATURE: &str = include_str!("test_data/b26_signature");

        let public_key = PublicKey::from_pem_text(
            "test-key-ed25519",
            PUBLIC_KEY_TEXT,
            Some("ed25519"),
        ).unwrap();

        assert!(public_key.verify_base64(SIGNATURE_BASE, SIGNATURE));
    }
}