//! `OpenBox` supervisor middleware for `OpenShell`: every policy-admitted
//! outbound request from a sandbox gets an `OpenBox` verdict before `OpenShell`
//! injects credentials and forwards it.

#![forbid(unsafe_code)]

pub mod action;
pub mod core_client;
pub mod front_desk;
pub mod guard;
pub mod halt;
pub mod interceptor;
pub mod inventory;
pub mod metrics;
pub mod service;
pub mod token;
