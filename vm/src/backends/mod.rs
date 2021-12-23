//! Virtual machine backend

#[cfg(target_os = "linux")]
pub mod kvm;

#[cfg(target_os = "windows")]
pub mod hyperv;
