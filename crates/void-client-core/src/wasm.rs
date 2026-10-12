use wasm_bindgen::prelude::*;

use crate::{DeviceIdentity, VaultError};

#[wasm_bindgen]
pub struct BrowserDeviceIdentity {
    identity: DeviceIdentity,
}

#[wasm_bindgen]
impl BrowserDeviceIdentity {
    #[wasm_bindgen(constructor)]
    pub fn create(identity: &[u8], passphrase: &str) -> Result<BrowserDeviceIdentity, JsValue> {
        let identity = DeviceIdentity::generate(identity.to_vec(), passphrase).map_err(js_error)?;
        Ok(Self { identity })
    }

    pub fn unlock(vault: &[u8], passphrase: &str) -> Result<BrowserDeviceIdentity, JsValue> {
        let identity = DeviceIdentity::unlock(vault, passphrase).map_err(js_error)?;
        Ok(Self { identity })
    }

    pub fn identity(&self) -> Vec<u8> {
        self.identity.identity().to_vec()
    }

    pub fn signing_public_key(&self) -> Vec<u8> {
        self.identity.signing_public_key().to_vec()
    }

    pub fn seal(&self, passphrase: &str) -> Result<Vec<u8>, JsValue> {
        self.identity.seal(passphrase).map_err(js_error)
    }

    pub fn lock(self) {
        self.identity.lock();
    }
}

fn js_error(error: VaultError) -> JsValue {
    JsValue::from_str(&error.to_string())
}
