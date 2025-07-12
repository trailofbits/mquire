//
// Copyright (c) 2025-present, Trail of Bits, Inc.
// All rights reserved.
//
// This source code is licensed in accordance with the terms specified in
// the LICENSE file found in the root directory of this source tree.
//

use crate::core::{
    entities::{
        file::File, system_information::SystemInformation, system_version::SystemVersion,
        task::Task,
    },
    error::Result,
};

/// Common interface for operating system implementations.
pub trait OperatingSystem {
    /// Returns the OS version.
    fn get_os_version(&self) -> Result<SystemVersion>;

    /// Returns the system information.
    fn get_system_information(&self) -> Result<SystemInformation>;

    /// Returns the task list.
    fn get_task_list(&self) -> Result<Vec<Task>>;

    /// Returns the list of open files.
    fn get_task_open_file_list(&self) -> Result<Vec<File>>;
}
