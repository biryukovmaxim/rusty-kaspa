use crate::accounts::account::WalletAccountTrait;
use crate::accounts::WalletAccount;
use crate::Result;
use kaspa_bip32::{ExtendedPrivateKey, SecretKey};
use serde_wasm_bindgen::to_value;
use std::str::FromStr;
use wasm_bindgen::prelude::*;

#[wasm_bindgen]
pub struct XPublicKey {
    hd_wallet: WalletAccount,
}
#[wasm_bindgen]
impl XPublicKey {
    // #[wasm_bindgen(constructor)]
    // pub async fn new(kpub: &str, is_multisig: bool, account_index: u64) -> Result<XPublicKey> {
    //     let xpub = ExtendedPublicKey::<secp256k1::PublicKey>::from_str(kpub)?;
    //     Self::from_xpublic_key(xpub, is_multisig, account_index).await
    // }

    #[wasm_bindgen(js_name=fromXPrv)]
    pub async fn from_xprv(xprv: &str, is_multisig: bool, account_index: u64) -> Result<XPublicKey> {
        let xprv = ExtendedPrivateKey::<SecretKey>::from_str(xprv)?;
        let path = WalletAccount::build_derivate_path(is_multisig, account_index, None)?;
        let xprv = xprv.derive_path(path)?;
        let xpub = xprv.public_key();
        let hd_wallet = WalletAccount::from_extended_public_key(xpub).await?;
        Ok(Self { hd_wallet })
    }

    #[wasm_bindgen(js_name=receiveAddresses)]
    pub async fn receive_addresses(&self, mut start: u32, mut end: u32) -> Result<JsValue> {
        if start > end {
            (start, end) = (end, start);
        }
        let addresses = self.hd_wallet.receive_wallet().derive_addresses(start..end).await?;
        let addresses = to_value(&addresses)?;
        Ok(addresses)
    }

    #[wasm_bindgen(js_name=changeAddresses)]
    pub async fn change_addresses(&self, mut start: u32, mut end: u32) -> Result<JsValue> {
        if start > end {
            (start, end) = (end, start);
        }
        let addresses = self.hd_wallet.change_wallet().derive_addresses(start..end).await?;
        let addresses = to_value(&addresses)?;
        Ok(addresses)
    }
}