//! Talking to Konklav: requests described as data, the endpoints the
//! console uses, the DTOs it reads, and a `fetch` transport.

mod dpop;
pub mod endpoints;
mod error;
mod request;
mod transport;
pub mod types;

pub use dpop::scheme;
pub use error::{ApiError, decode};
pub use request::{CLIENT_HEADER, Method, Request, Surface, encode};
pub use transport::send;
