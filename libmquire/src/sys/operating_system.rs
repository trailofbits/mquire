//
// Copyright (c) 2025-present, Trail of Bits, Inc.
// All rights reserved.
//
// This source code is licensed in accordance with the terms specified in
// the LICENSE file found in the root directory of this source tree.
//

use std::any::Any;
use std::sync::Arc;

use crate::memory::Readable;
use crate::sys::{
    entities::{File, OSVersion, SystemInformation, Task},
    Architecture, Result as SystemResult,
};

/// Private, per-instance data for OperatingSystem implementations
pub trait OperatingSystemData {
    /// Converts the `OperatingSystemData` into a `dyn Any` reference (used for downcasting)
    fn as_any(&self) -> &dyn Any;

    /// Converts the `OperatingSystemData` into a mutable `dyn Any` reference (used for downcasting)
    fn as_mut_any(&mut self) -> &mut dyn Any;
}

/// Common interface for operating system implementations
pub trait OperatingSystem {
    /// Initializes the operating system data
    fn initialize(
        &self,
        readable: &dyn Readable,
        architecture: &dyn Architecture,
    ) -> SystemResult<Arc<dyn OperatingSystemData>>;

    /// Returns the OS version
    fn get_os_version(
        &self,
        readable: &dyn Readable,
        architecture: &dyn Architecture,
        operating_system_data: &Arc<dyn OperatingSystemData>,
    ) -> SystemResult<OSVersion>;

    /// Returns the system information
    fn get_system_information(
        &self,
        readable: &dyn Readable,
        architecture: &dyn Architecture,
        operating_system_data: &Arc<dyn OperatingSystemData>,
    ) -> SystemResult<SystemInformation>;

    /// Returns the task list
    fn get_task_list(
        &self,
        readable: &dyn Readable,
        architecture: &dyn Architecture,
        operating_system_data: &Arc<dyn OperatingSystemData>,
    ) -> SystemResult<Vec<Task>>;

    /// Returns the list of files opened by the given task
    fn get_task_open_file_list(
        &self,
        readable: &dyn Readable,
        architecture: &dyn Architecture,
        operating_system_data: &Arc<dyn OperatingSystemData>,
    ) -> SystemResult<Vec<File>>;
}
