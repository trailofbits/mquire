//
// Copyright (c) 2025-present, Trail of Bits, Inc.
// All rights reserved.
//
// This source code is licensed in accordance with the terms specified in
// the LICENSE file found in the root directory of this source tree.
//

use std::sync::Arc;

use crate::memory::Readable;
use crate::sys::{
    entities::{File, OSVersion, SystemInformation, Task},
    Architecture, OperatingSystem, OperatingSystemData, Result,
};

/// Represents the analyzed system
pub struct System<'a> {
    /// The memory dump
    memory_dump: &'a dyn Readable,

    /// The target architecture
    architecture: &'a dyn Architecture,

    /// The operating system implementation
    operating_system: &'a dyn OperatingSystem,

    /// The private OperatingSystem data
    operating_system_data: Arc<dyn OperatingSystemData>,
}

impl<'a> System<'a> {
    /// Creates a new system instance
    pub fn new(
        memory_dump: &'a dyn Readable,
        architecture: &'a dyn Architecture,
        operating_system: &'a dyn OperatingSystem,
    ) -> Result<Self> {
        let operating_system_data = operating_system.initialize(memory_dump, architecture)?;

        Ok(Self {
            memory_dump,
            architecture,
            operating_system,
            operating_system_data,
        })
    }

    /// Returns the OS version
    pub fn get_os_version(&self) -> Result<OSVersion> {
        self.operating_system.get_os_version(
            self.memory_dump,
            self.architecture,
            &self.operating_system_data,
        )
    }

    /// Returns the system information
    pub fn get_system_information(&self) -> Result<SystemInformation> {
        self.operating_system.get_system_information(
            self.memory_dump,
            self.architecture,
            &self.operating_system_data,
        )
    }

    /// Returns the task list
    pub fn get_task_list(&self) -> Result<Vec<Task>> {
        self.operating_system.get_task_list(
            self.memory_dump,
            self.architecture,
            &self.operating_system_data,
        )
    }

    /// Returns the list of files opened by the given task
    pub fn get_task_open_file_list(&self) -> Result<Vec<File>> {
        self.operating_system.get_task_open_file_list(
            self.memory_dump,
            self.architecture,
            &self.operating_system_data,
        )
    }
}
