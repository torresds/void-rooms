#![forbid(unsafe_code)]

mod identity;
mod vault;

#[cfg(not(target_arch = "wasm32"))]
pub mod storage;

#[cfg(target_arch = "wasm32")]
mod wasm;

pub use identity::DeviceIdentity;
pub use vault::{MAX_VAULT_SIZE, VaultError};
