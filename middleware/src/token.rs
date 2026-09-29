//! Verification of the short-lived bearer token `OpenShell` attaches to every
//! supervisor middleware call.
//!
//! The token is a compact JWS with `typ = "openshell-ext+jwt"` and
//! `alg = "EdDSA"`, signed with the gateway's Ed25519 key. The algorithm is
//! pinned here and never read from the token. Claims checked on every call:
//! signature, expiry (with a small leeway), exact audience, the
//! `openshell-gateway:<gateway_id>` issuer, and the caller kind. A repeated
//! `jti` is accepted because `OpenShell` reuses a token until it rotates.

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ring::signature::{ED25519, UnparsedPublicKey};
use serde::Deserialize;

const TOKEN_TYPE: &str = "openshell-ext+jwt";
const ALGORITHM: &str = "EdDSA";
/// DER prefix of an Ed25519 `SubjectPublicKeyInfo`; the 32-byte key follows.
const ED25519_SPKI_PREFIX: [u8; 12] = [
    0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
];
const MAX_TOKEN_BYTES: usize = 8 * 1024;

/// Who inside `OpenShell` made the call.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Caller {
    /// The gateway itself, e.g. `Describe` and `ValidateConfig` at startup.
    Gateway,
    /// A sandbox supervisor evaluating traffic for one sandbox.
    Supervisor { sandbox_id: String },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TokenError {
    Malformed,
    UnexpectedHeader,
    BadSignature,
    Expired,
    NotYetValid,
    WrongIssuer,
    WrongAudience,
    UnknownCaller,
}

impl core::fmt::Display for TokenError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str(match self {
            Self::Malformed => "malformed extension token",
            Self::UnexpectedHeader => "extension token header is not openshell-ext+jwt / EdDSA",
            Self::BadSignature => "extension token signature is invalid",
            Self::Expired => "extension token has expired",
            Self::NotYetValid => "extension token is not yet valid",
            Self::WrongIssuer => "extension token issuer is not the configured gateway",
            Self::WrongAudience => "extension token audience does not match",
            Self::UnknownCaller => "extension token caller is not a gateway or supervisor",
        })
    }
}

impl std::error::Error for TokenError {}

/// Verifies extension tokens from one configured gateway.
#[derive(Clone)]
pub struct TokenVerifier {
    public_key: [u8; 32],
    issuer: String,
    audience: String,
    leeway_secs: i64,
}

impl core::fmt::Debug for TokenVerifier {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("TokenVerifier")
            .field("issuer", &self.issuer)
            .field("audience", &self.audience)
            .finish_non_exhaustive()
    }
}

#[derive(Deserialize)]
struct Header {
    typ: Option<String>,
    alg: Option<String>,
}

#[derive(Deserialize)]
#[serde(untagged)]
enum Audience {
    One(String),
    Many(Vec<String>),
}

#[derive(Deserialize)]
struct Claims {
    iss: Option<String>,
    aud: Option<Audience>,
    exp: Option<i64>,
    nbf: Option<i64>,
    caller_kind: Option<String>,
    sandbox_id: Option<String>,
}

impl TokenVerifier {
    /// Builds a verifier from the gateway's public key in PEM
    /// (`-----BEGIN PUBLIC KEY-----`) form.
    pub fn from_pem(
        public_key_pem: &str,
        gateway_id: &str,
        audience: impl Into<String>,
    ) -> Result<Self, TokenError> {
        let body: String = public_key_pem
            .lines()
            .filter(|line| !line.starts_with("-----"))
            .map(str::trim)
            .collect();
        let der = base64::engine::general_purpose::STANDARD
            .decode(body)
            .map_err(|_| TokenError::Malformed)?;
        let key = der
            .strip_prefix(&ED25519_SPKI_PREFIX)
            .and_then(|key| <[u8; 32]>::try_from(key).ok())
            .ok_or(TokenError::Malformed)?;
        let audience = audience.into();
        if gateway_id.is_empty() || audience.is_empty() {
            return Err(TokenError::Malformed);
        }
        Ok(Self {
            public_key: key,
            issuer: format!("openshell-gateway:{gateway_id}"),
            audience,
            leeway_secs: 30,
        })
    }

    pub fn audience(&self) -> &str {
        &self.audience
    }

    /// Verifies a token at `now` (Unix seconds) and returns the caller.
    pub fn verify(&self, token: &str, now: i64) -> Result<Caller, TokenError> {
        if token.len() > MAX_TOKEN_BYTES {
            return Err(TokenError::Malformed);
        }
        let mut parts = token.split('.');
        let (Some(header_b64), Some(claims_b64), Some(signature_b64), None) =
            (parts.next(), parts.next(), parts.next(), parts.next())
        else {
            return Err(TokenError::Malformed);
        };
        let header: Header = decode_json(header_b64)?;
        if header.typ.as_deref() != Some(TOKEN_TYPE) || header.alg.as_deref() != Some(ALGORITHM) {
            return Err(TokenError::UnexpectedHeader);
        }
        let signature = URL_SAFE_NO_PAD
            .decode(signature_b64)
            .map_err(|_| TokenError::Malformed)?;
        let signed = &token[..header_b64.len() + 1 + claims_b64.len()];
        UnparsedPublicKey::new(&ED25519, &self.public_key)
            .verify(signed.as_bytes(), &signature)
            .map_err(|_| TokenError::BadSignature)?;

        let claims: Claims = decode_json(claims_b64)?;
        let exp = claims.exp.ok_or(TokenError::Malformed)?;
        if now > exp.saturating_add(self.leeway_secs) {
            return Err(TokenError::Expired);
        }
        if claims
            .nbf
            .is_some_and(|nbf| now.saturating_add(self.leeway_secs) < nbf)
        {
            return Err(TokenError::NotYetValid);
        }
        if claims.iss.as_deref() != Some(self.issuer.as_str()) {
            return Err(TokenError::WrongIssuer);
        }
        let audience_matches = match &claims.aud {
            Some(Audience::One(aud)) => aud == &self.audience,
            Some(Audience::Many(auds)) => auds.iter().any(|aud| aud == &self.audience),
            None => false,
        };
        if !audience_matches {
            return Err(TokenError::WrongAudience);
        }
        match (claims.caller_kind.as_deref(), claims.sandbox_id) {
            (Some("gateway"), _) => Ok(Caller::Gateway),
            (Some("supervisor"), Some(sandbox_id)) if !sandbox_id.is_empty() => {
                Ok(Caller::Supervisor { sandbox_id })
            }
            _ => Err(TokenError::UnknownCaller),
        }
    }
}

fn decode_json<T: for<'de> Deserialize<'de>>(segment: &str) -> Result<T, TokenError> {
    let bytes = URL_SAFE_NO_PAD
        .decode(segment)
        .map_err(|_| TokenError::Malformed)?;
    serde_json::from_slice(&bytes).map_err(|_| TokenError::Malformed)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use ring::rand::SystemRandom;
    use ring::signature::{Ed25519KeyPair, KeyPair as _};

    pub struct TestSigner {
        pair: Ed25519KeyPair,
    }

    impl TestSigner {
        pub fn new() -> Self {
            let pkcs8 = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new()).unwrap();
            Self {
                pair: Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).unwrap(),
            }
        }

        pub fn public_pem(&self) -> String {
            let mut der = ED25519_SPKI_PREFIX.to_vec();
            der.extend_from_slice(self.pair.public_key().as_ref());
            format!(
                "-----BEGIN PUBLIC KEY-----\n{}\n-----END PUBLIC KEY-----\n",
                base64::engine::general_purpose::STANDARD.encode(der)
            )
        }

        pub fn sign(&self, header: &serde_json::Value, claims: &serde_json::Value) -> String {
            let signed = format!(
                "{}.{}",
                URL_SAFE_NO_PAD.encode(header.to_string()),
                URL_SAFE_NO_PAD.encode(claims.to_string())
            );
            let signature = self.pair.sign(signed.as_bytes());
            format!("{signed}.{}", URL_SAFE_NO_PAD.encode(signature.as_ref()))
        }

        pub fn supervisor_token(&self, sandbox_id: &str, exp: i64) -> String {
            self.sign(
                &serde_json::json!({"typ": TOKEN_TYPE, "alg": ALGORITHM}),
                &serde_json::json!({
                    "iss": "openshell-gateway:gw-1",
                    "aud": AUDIENCE,
                    "exp": exp,
                    "caller_kind": "supervisor",
                    "sandbox_id": sandbox_id,
                }),
            )
        }
    }

    pub const AUDIENCE: &str = "urn:openshell:extension:middleware:openbox";
    const NOW: i64 = 1_800_000_000;

    fn verifier(signer: &TestSigner) -> TokenVerifier {
        TokenVerifier::from_pem(&signer.public_pem(), "gw-1", AUDIENCE).unwrap()
    }

    fn claims() -> serde_json::Value {
        serde_json::json!({
            "iss": "openshell-gateway:gw-1",
            "aud": AUDIENCE,
            "exp": NOW + 60,
            "caller_kind": "supervisor",
            "sandbox_id": "sbx-id-1",
        })
    }

    fn header() -> serde_json::Value {
        serde_json::json!({"typ": TOKEN_TYPE, "alg": ALGORITHM})
    }

    #[test]
    fn accepts_a_valid_supervisor_token() {
        let signer = TestSigner::new();
        let token = signer.sign(&header(), &claims());
        assert_eq!(
            verifier(&signer).verify(&token, NOW),
            Ok(Caller::Supervisor {
                sandbox_id: "sbx-id-1".to_owned()
            })
        );
    }

    #[test]
    fn accepts_a_gateway_token_and_audience_lists() {
        let signer = TestSigner::new();
        let mut claims = claims();
        claims["caller_kind"] = "gateway".into();
        claims["aud"] = serde_json::json!(["other", AUDIENCE]);
        let token = signer.sign(&header(), &claims);
        assert_eq!(verifier(&signer).verify(&token, NOW), Ok(Caller::Gateway));
    }

    #[test]
    fn rejects_a_token_signed_by_another_key() {
        let signer = TestSigner::new();
        let token = TestSigner::new().sign(&header(), &claims());
        assert_eq!(
            verifier(&signer).verify(&token, NOW),
            Err(TokenError::BadSignature)
        );
    }

    #[test]
    fn rejects_tampered_claims() {
        let signer = TestSigner::new();
        let token = signer.sign(&header(), &claims());
        let mut forged = claims();
        forged["sandbox_id"] = "sbx-other".into();
        let parts: Vec<&str> = token.split('.').collect();
        let tampered = format!(
            "{}.{}.{}",
            parts[0],
            URL_SAFE_NO_PAD.encode(forged.to_string()),
            parts[2]
        );
        assert_eq!(
            verifier(&signer).verify(&tampered, NOW),
            Err(TokenError::BadSignature)
        );
    }

    #[test]
    fn pins_type_and_algorithm() {
        let signer = TestSigner::new();
        for header in [
            serde_json::json!({"typ": "JWT", "alg": ALGORITHM}),
            serde_json::json!({"typ": TOKEN_TYPE, "alg": "none"}),
            serde_json::json!({"typ": TOKEN_TYPE, "alg": "HS256"}),
            serde_json::json!({"alg": ALGORITHM}),
        ] {
            let token = signer.sign(&header, &claims());
            assert_eq!(
                verifier(&signer).verify(&token, NOW),
                Err(TokenError::UnexpectedHeader)
            );
        }
    }

    #[test]
    fn enforces_expiry_with_leeway() {
        let signer = TestSigner::new();
        let token = signer.sign(&header(), &claims());
        assert!(verifier(&signer).verify(&token, NOW + 60 + 30).is_ok());
        assert_eq!(
            verifier(&signer).verify(&token, NOW + 60 + 31),
            Err(TokenError::Expired)
        );
        let mut no_exp = claims();
        no_exp.as_object_mut().unwrap().remove("exp");
        assert_eq!(
            verifier(&signer).verify(&signer.sign(&header(), &no_exp), NOW),
            Err(TokenError::Malformed)
        );
    }

    #[test]
    fn rejects_early_tokens() {
        let signer = TestSigner::new();
        let mut early = claims();
        early["nbf"] = (NOW + 120).into();
        assert_eq!(
            verifier(&signer).verify(&signer.sign(&header(), &early), NOW),
            Err(TokenError::NotYetValid)
        );
    }

    #[test]
    fn checks_issuer_audience_and_caller() {
        let signer = TestSigner::new();
        let cases = [
            (
                "iss",
                serde_json::json!("https://gateway.example"),
                TokenError::WrongIssuer,
            ),
            (
                "iss",
                serde_json::json!("openshell-gateway:gw-2"),
                TokenError::WrongIssuer,
            ),
            (
                "aud",
                serde_json::json!("urn:openshell:extension:middleware:other"),
                TokenError::WrongAudience,
            ),
            (
                "caller_kind",
                serde_json::json!("sandbox"),
                TokenError::UnknownCaller,
            ),
            (
                "sandbox_id",
                serde_json::json!(""),
                TokenError::UnknownCaller,
            ),
        ];
        for (field, value, expected) in cases {
            let mut claims = claims();
            claims[field] = value;
            assert_eq!(
                verifier(&signer).verify(&signer.sign(&header(), &claims), NOW),
                Err(expected),
                "{field}"
            );
        }
    }

    #[test]
    fn rejects_malformed_tokens() {
        let signer = TestSigner::new();
        for token in [
            "",
            "a.b",
            "a.b.c.d",
            "!!.!!.!!",
            &"a".repeat(MAX_TOKEN_BYTES + 1),
        ] {
            assert!(verifier(&signer).verify(token, NOW).is_err(), "{token:.20}");
        }
    }

    #[test]
    fn rejects_non_ed25519_public_keys() {
        assert_eq!(
            TokenVerifier::from_pem(
                "-----BEGIN PUBLIC KEY-----\nAAAA\n-----END PUBLIC KEY-----",
                "gw",
                AUDIENCE
            )
            .unwrap_err(),
            TokenError::Malformed
        );
    }
}
