//
// Copyright (c) 2025-present, Trail of Bits, Inc.
// All rights reserved.
//
// This source code is licensed in accordance with the terms specified in
// the LICENSE file found in the root directory of this source tree.
//

use crate::{
    core::{
        entities::{
            file::File, network_interface::NetworkInterface, system_information::SystemInformation,
            system_version::SystemVersion,
        },
        error::Result,
    },
    memory::{readable::Readable, virtual_address::VirtualAddress},
};

use std::{any::Any, sync::Arc};

/// Common interface for operating system implementations.
pub trait OperatingSystem: Send + Sync + Any {
    /// Returns the OS version.
    fn get_os_version(&self) -> Result<SystemVersion>;

    /// Returns the system information.
    fn get_system_information(&self) -> Result<SystemInformation>;

    /// Returns the list of open files.
    fn get_task_open_file_list(&self) -> Result<Vec<File>>;

    /// Returns the network interface list.
    fn get_network_interface_list(&self) -> Result<Vec<NetworkInterface>>;

    /// Returns a reader for the file struct at the given virtual address.
    fn get_file_reader(&self, file: VirtualAddress) -> Result<Arc<dyn Readable>>;

    /// Converts this Arc to an Arc<dyn Any> for downcasting.
    fn as_any_arc(self: Arc<Self>) -> Arc<dyn Any + Send + Sync>;
}
