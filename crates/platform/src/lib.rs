//! Operating-system boundaries shared by native integrations.

#![cfg_attr(
    all(target_os = "windows", test, feature = "registry-witness"),
    windows_subsystem = "windows"
)]

pub mod fs;
pub mod process;
