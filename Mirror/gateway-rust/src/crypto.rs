// -----------------------------------------------------------------------------
// Author  : MingTea
// File    : crypto.rs
// Created : 2026-09-22
// Summary : 敏感凭据加解密（AES-256-GCM + enc:v1: 封套 + base64url 无填充）。
// 证据来源：reverse/reports/05-database-schema.md §6、04-gateway-disassembly.md §3.2-3.4。
// -----------------------------------------------------------------------------

//! 敏感凭据加解密模块。
//!
//! 复刻 chatgpt-mirror-gateway 的 `db::encrypt_secret` / `db::decrypt_secret`
//! 文本封套：密文列存 `enc:v1:` + base64url(无填充)(nonce[12] || ciphertext+tag)；
//! 密钥由 `SHA-256(trim(key))` 派生（原版 `credential_key` 行为，报告 §3.2）。
//! 两端都保持原版的透传语义：加密对已带前缀的输入幂等，解密对非密文原样返回。

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use anyhow::{anyhow, bail, Result};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use rand::rngs::OsRng;
use rand::RngCore;
use sha2::{Digest, Sha256};

/// 密文封套前缀（原版 @0xD8C699）。
pub const ENC_PREFIX: &str = "enc:v1:";
/// mirror_token 摘要前缀（原版 @0xD8C87C）。
pub const SHA256_PREFIX: &str = "sha256:";
/// AES-GCM nonce 长度（原版 0xc = 12 字节）。
pub const NONCE_LEN: usize = 12;
/// 密钥 trim 后的最小字节长度（原版 0x20 = 32）。
pub const MIN_KEY_LEN: usize = 32;

/// 持有派生密钥的 AES-256-GCM 加密器。
pub struct Crypto {
    cipher: Aes256Gcm,
}

impl Crypto {
    /// 由外部密钥串创建：trim 后须不少于 32 字节，再经 SHA-256 派生 32 字节密钥。
    pub fn new(key: &str) -> Result<Self> {
        let trimmed = key.trim();
        if trimmed.len() < MIN_KEY_LEN {
            bail!("CREDENTIAL_ENCRYPTION_KEY 长度至少需要 32 字节");
        }
        let digest = Sha256::digest(trimmed.as_bytes());
        let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(digest.as_slice()));
        Ok(Self { cipher })
    }

    /// 是否已带 `enc:v1:` 封套。
    pub fn is_encrypted(value: &str) -> bool {
        value.starts_with(ENC_PREFIX)
    }

    /// 加密明文：已加密输入原样返回（幂等，对应原版 encrypt_secret）。
    pub fn encrypt(&self, value: &str) -> Result<String> {
        if Self::is_encrypted(value) {
            return Ok(value.to_string());
        }
        let mut nonce_bytes = [0u8; NONCE_LEN];
        OsRng.fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);
        let ciphertext = self
            .cipher
            .encrypt(nonce, value.as_bytes())
            .map_err(|_| anyhow!("敏感凭据加密失败"))?;
        let mut envelope = Vec::with_capacity(NONCE_LEN + ciphertext.len());
        envelope.extend_from_slice(&nonce_bytes);
        envelope.extend_from_slice(&ciphertext);
        Ok(format!("{ENC_PREFIX}{}", URL_SAFE_NO_PAD.encode(envelope)))
    }

    /// 解密：非 `enc:v1:` 输入原样透传（对应原版 decrypt_secret 的明文分支）。
    pub fn decrypt(&self, value: &str) -> Result<String> {
        let encoded = match value.strip_prefix(ENC_PREFIX) {
            Some(rest) => rest,
            None => return Ok(value.to_string()),
        };
        let decoded = URL_SAFE_NO_PAD
            .decode(encoded)
            .map_err(|_| anyhow!("敏感凭据编码损坏"))?;
        if decoded.len() <= NONCE_LEN {
            bail!("敏感凭据解密失败（数据长度不足）");
        }
        let (nonce_bytes, ciphertext) = decoded.split_at(NONCE_LEN);
        let nonce = Nonce::from_slice(nonce_bytes);
        let plaintext = self
            .cipher
            .decrypt(nonce, ciphertext)
            .map_err(|_| anyhow!("敏感凭据解密失败（密钥错误或数据损坏）"))?;
        String::from_utf8(plaintext).map_err(|_| anyhow!("敏感凭据解密结果不是合法 UTF-8"))
    }
}

/// mirror_token 摘要：`sha256:` + 小写 hex（对应原版 mirror_token_hash）。
pub fn sha256_hex(value: &str) -> String {
    let digest = Sha256::digest(value.as_bytes());
    let hex: String = digest.iter().map(|byte| format!("{byte:02x}")).collect();
    format!("{SHA256_PREFIX}{hex}")
}

/// 是否已带 `sha256:` 前缀（原版迁移路径按此前缀跳过重复哈希）。
pub fn is_sha256_hashed(value: &str) -> bool {
    value.starts_with(SHA256_PREFIX)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_and_prefix_rules() {
        let crypto = Crypto::new(&"k".repeat(32)).expect("创建加密器失败");
        let encrypted = crypto.encrypt("hello-秘密").expect("加密失败");
        assert!(encrypted.starts_with(ENC_PREFIX));
        assert_eq!(crypto.decrypt(&encrypted).expect("解密失败"), "hello-秘密");
        // 已加密输入原样返回（幂等）
        assert_eq!(crypto.encrypt(&encrypted).expect("幂等加密失败"), encrypted);
        // 非密文输入原样透传
        assert_eq!(crypto.decrypt("plain").expect("透传失败"), "plain");
        // 每次加密 nonce 随机
        assert_ne!(crypto.encrypt("hello-秘密").expect("加密失败"), encrypted);
    }

    #[test]
    fn wrong_key_and_bad_payload_fail() {
        let crypto = Crypto::new(&"a".repeat(32)).expect("创建加密器失败");
        let other = Crypto::new(&"b".repeat(32)).expect("创建加密器失败");
        let encrypted = crypto.encrypt("secret").expect("加密失败");
        assert!(other.decrypt(&encrypted).is_err(), "错误密钥必须报错");
        assert!(
            crypto.decrypt("enc:v1:not-base64!!").is_err(),
            "编码损坏必须报错"
        );
        assert!(crypto.decrypt("enc:v1:AAAA").is_err(), "长度不足必须报错");
    }

    #[test]
    fn key_min_length_enforced() {
        assert!(Crypto::new(&"k".repeat(31)).is_err());
        assert!(Crypto::new(&format!("  {}  ", "k".repeat(32))).is_ok());
    }

    #[test]
    fn sha256_prefix_hash() {
        // 已知向量：SHA-256("abc")
        assert_eq!(
            sha256_hex("abc"),
            "sha256:ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert!(is_sha256_hashed("sha256:00"));
        assert!(!is_sha256_hashed("raw-token"));
    }
}
