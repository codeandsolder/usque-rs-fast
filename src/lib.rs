#![deny(unsafe_code)]
#![cfg_attr(
    not(test),
    deny(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::todo,
        clippy::unimplemented
    )
)]
#![warn(
    clippy::all,
    clippy::pedantic,
    clippy::nursery,
    clippy::cargo,
    rust_2018_idioms
)]
#![allow(
    clippy::module_name_repetitions,
    clippy::must_use_candidate,
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::cast_precision_loss,
    clippy::multiple_crate_versions,
    clippy::redundant_pub_crate,
    clippy::similar_names,
    clippy::fn_params_excessive_bools,
    clippy::large_futures,
    clippy::items_after_statements,
    clippy::too_many_lines,
    clippy::cargo_common_metadata
)]

pub mod config;
pub mod icmp;
pub mod packet;
pub mod packet_session;
pub mod register;
pub mod tls;
pub mod tun_device;
pub mod tunnel;
mod udp_socket;

pub use packet_session::MasquePacketStream;
