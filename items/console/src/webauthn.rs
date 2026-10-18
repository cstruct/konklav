//! The browser's Web Authentication API, through its JSON forms: Konklav's options
//! go to `PublicKeyCredential.parse*OptionsFromJSON`, and the resulting
//! credential comes back through `toJSON()`, so no binary fields are
//! converted here.

use js_sys::{Function, JSON, Object, Promise, Reflect};
use serde_json::Value;
use wasm_bindgen::{JsCast, JsValue};
use wasm_bindgen_futures::JsFuture;

use crate::api::ApiError;

fn failed(message: impl Into<String>) -> ApiError {
    ApiError::Api {
        status: 0,
        code: "PASSKEY_UNAVAILABLE".to_owned(),
        message: message.into(),
    }
}

fn get(target: &JsValue, name: &str) -> Result<JsValue, ApiError> {
    Reflect::get(target, &JsValue::from_str(name))
        .map_err(|_| failed(format!("this browser has no `{name}`")))
}

fn function(target: &JsValue, name: &str) -> Result<Function, ApiError> {
    get(target, name)?
        .dyn_into::<Function>()
        .map_err(|_| failed("this browser doesn't support passkeys"))
}

fn to_js(value: &Value) -> Result<JsValue, ApiError> {
    JSON::parse(&value.to_string()).map_err(|_| failed("could not read the passkey options"))
}

fn from_js(value: &JsValue) -> Result<Value, ApiError> {
    let text: String = JSON::stringify(value)
        .map_err(|_| failed("could not read the passkey"))?
        .into();
    serde_json::from_str(&text).map_err(|error| failed(error.to_string()))
}

/// Calls `navigator.credentials.<method>` with `options.publicKey` parsed
/// by `parser`, and returns the credential's JSON form.
async fn ceremony(options: &Value, parser: &str, method: &str) -> Result<Value, ApiError> {
    let window: JsValue = web_sys::window()
        .ok_or_else(|| failed("no browser window"))?
        .into();
    let class = get(&window, "PublicKeyCredential")?;
    let parsed = function(&class, parser)?
        .call1(&class, &to_js(&options["publicKey"])?)
        .map_err(|error| failed(describe(&error)))?;
    let request = Object::new();
    Reflect::set(&request, &"publicKey".into(), &parsed)
        .map_err(|_| failed("could not build the request"))?;
    if let Some(mediation) = options["mediation"].as_str() {
        Reflect::set(&request, &"mediation".into(), &mediation.into())
            .map_err(|_| failed("could not build the request"))?;
    }
    let credentials = get(&get(&window, "navigator")?, "credentials")?;
    let promise: Promise = function(&credentials, method)?
        .call1(&credentials, &request)
        .map_err(|error| failed(describe(&error)))?
        .dyn_into()
        .map_err(|_| failed("the browser did not start the ceremony"))?;
    let credential = JsFuture::from(promise)
        .await
        .map_err(|error| failed(describe(&error)))?;
    if credential.is_null() {
        return Err(failed("no passkey was chosen"));
    }
    let json = function(&credential, "toJSON")?
        .call0(&credential)
        .map_err(|error| failed(describe(&error)))?;
    from_js(&json)
}

/// A browser error's message, such as a cancelled prompt's.
fn describe(error: &JsValue) -> String {
    Reflect::get(error, &"message".into())
        .ok()
        .and_then(|message| message.as_string())
        .unwrap_or_else(|| "the passkey prompt failed".to_owned())
}

/// Creates a passkey from Konklav's registration options.
///
/// # Errors
///
/// When the browser lacks passkey support or the person cancels.
pub async fn create(options: &Value) -> Result<Value, ApiError> {
    ceremony(options, "parseCreationOptionsFromJSON", "create").await
}

/// Signs Konklav's login or step-up options with a passkey.
///
/// # Errors
///
/// As [`create`].
pub async fn sign(options: &Value) -> Result<Value, ApiError> {
    ceremony(options, "parseRequestOptionsFromJSON", "get").await
}
