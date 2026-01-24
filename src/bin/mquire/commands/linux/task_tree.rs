//
// Copyright (c) 2025-present, Trail of Bits, Inc.
// All rights reserved.
//
// This source code is licensed in accordance with the terms specified in
// the LICENSE file found in the root directory of this source tree.
//

use crate::commands::command_registry::{Command, CommandContext};

use mquire::operating_system::linux::{
    entities::task::Task, operating_system::LinuxOperatingSystem,
};

use {
    clap::{Parser, error::ErrorKind as ClapErrorKind},
    log::debug,
};

use std::{
    collections::{BTreeMap, BTreeSet},
    io,
};

/// Display a hierarchical task tree
#[derive(Parser, Debug)]
#[command(name = "task_tree")]
#[command(about = "Display a hierarchical task tree", long_about = None)]
struct TaskTreeArgs {
    /// Use real_parent instead of parent for the tree structure
    #[arg(long)]
    use_real_parent: bool,

    /// Show threads in addition to processes
    #[arg(long, default_value_t = false)]
    show_threads: bool,
}

/// State for tree printing that gets passed through recursive calls
#[derive(Default)]
struct TreeState {
    /// Maps a task tid to the tid values of its children
    children_map: BTreeMap<u32, Vec<u32>>,

    /// Maps a task tid to its tasks (can have multiple entries for duplicate TIDs)
    tid_to_tasks: BTreeMap<u32, Vec<Task>>,

    /// Maps a task tid to its tgid
    tid_to_tgid: BTreeMap<u32, u32>,
}

/// A command that displays the task tree, optionally showing threads
pub struct TaskTreeCommand;

impl TaskTreeCommand {
    pub fn new() -> Self {
        Self
    }

    /// Prints the tree to screen
    fn print_tree(state: &TreeState, tid: u32, prefix: &str, is_last: bool, display_tid: bool) {
        let pid = state
            .tid_to_tgid
            .get(&tid)
            .copied()
            .map(|tid| format!("{tid}"))
            .unwrap_or("?".to_owned());

        let pid_tid_str = if display_tid {
            format!("[{} {}]", pid, tid)
        } else {
            format!("[{}]", pid)
        };

        let task_list = state.tid_to_tasks.get(&tid).cloned().unwrap_or_default();

        for (index, task) in task_list.iter().enumerate() {
            let ascii_branch = match index {
                0 => {
                    if is_last {
                        "└─"
                    } else {
                        "├─"
                    }
                }

                _ => "╎   ↳",
            };

            let current_prefix = match index {
                0 => prefix.to_owned(),

                _ => {
                    format!("{}{}  ", prefix, if is_last { " " } else { "│" })
                }
            };

            let raw_virtual_addr = task.virtual_address.value();
            let name = task
                .name
                .as_ref()
                .map(|s| {
                    let mut result = String::new();

                    for c in s.chars() {
                        match c {
                            '\n' => result.push_str("\\n"),
                            '\r' => result.push_str("\\r"),
                            '\t' => result.push_str("\\t"),

                            c if c == ' ' || c.is_ascii_graphic() => result.push(c),

                            c => {
                                for byte in c.to_string().as_bytes() {
                                    result.push_str(&format!("\\x{:02x}", byte));
                                }
                            }
                        }
                    }

                    result
                })
                .unwrap_or_else(|| "?".to_string());

            println!(
                "{current_prefix}{ascii_branch} {pid_tid_str} ({:x}) {}",
                raw_virtual_addr.value(),
                name,
            );
        }

        if task_list.is_empty() {
            let ascii_branch = if is_last { "└─" } else { "├─" };
            println!("{prefix}{ascii_branch} {pid_tid_str} ?");
        }

        if let Some(children) = state.children_map.get(&tid) {
            let child_prefix = format!("{}{}  ", prefix, if is_last { " " } else { "│" });

            for (index, &child_tid) in children.iter().enumerate() {
                let is_last_child = index == children.len() - 1;
                Self::print_tree(state, child_tid, &child_prefix, is_last_child, display_tid);
            }
        }
    }
}

impl Command for TaskTreeCommand {
    fn name(&self) -> &str {
        "task_tree"
    }

    fn description(&self) -> &str {
        "Display a hierarchical task tree"
    }

    fn execute(&self, args: &str, context: &CommandContext) -> io::Result<()> {
        // TODO(alessandro): This should support iter_tasks + iter_tasks_from
        let args_vec: Vec<&str> = if args.is_empty() {
            vec!["task_tree"]
        } else {
            let mut v = vec!["task_tree"];
            v.extend(args.split_whitespace());

            v
        };

        let parsed_args = match TaskTreeArgs::try_parse_from(args_vec) {
            Ok(args) => args,

            Err(e) => {
                if e.kind() == ClapErrorKind::DisplayHelp
                    || e.kind() == ClapErrorKind::DisplayVersion
                {
                    print!("{}", e);
                    return Ok(());
                }

                return Err(io::Error::new(io::ErrorKind::InvalidInput, e.to_string()));
            }
        };

        let system = context
            .system
            .clone()
            .as_any_arc()
            .downcast::<LinuxOperatingSystem>()
            .map_err(|_| {
                io::Error::other("Failed to downcast to LinuxOperatingSystem".to_string())
            })?;

        let mut task_list: Vec<Task> = Vec::new();
        for task_result in system
            .iter_tasks()
            .map_err(|e| io::Error::other(format!("Failed to get task list: {:?}", e)))?
        {
            match task_result {
                Ok(task) => task_list.push(task),
                Err(err) => {
                    debug!("Failed to parse task: {err:?}");
                    continue;
                }
            }
        }

        let mut task_map: BTreeMap<u32, Vec<Task>> = BTreeMap::new();
        for task in task_list {
            task_map.entry(task.pid).or_default().push(task);
        }

        let mut tree_state = TreeState::default();
        let mut root_task_tid_list: Vec<u32> = Vec::new();
        let mut task_tid_list = BTreeSet::new();

        let page_table_address = task_map
            .values()
            .next()
            .and_then(|tasks| tasks.first())
            .map(|task| task.virtual_address.root_page_table())
            .unwrap_or_default();

        for (tid, tasks) in &task_map {
            let filtered_tasks: Vec<_> = tasks
                .iter()
                .filter(|task| {
                    let is_main_thread = task.tgid == task.pid;
                    parsed_args.show_threads || is_main_thread
                })
                .collect();

            if filtered_tasks.is_empty() {
                continue;
            }

            let primary_task = match filtered_tasks.first() {
                Some(&task) => task,
                None => continue,
            };

            if !tree_state.tid_to_tgid.contains_key(tid) {
                tree_state.tid_to_tgid.insert(*tid, primary_task.tgid);
            }

            if !filtered_tasks.is_empty() {
                tree_state.tid_to_tasks.insert(
                    *tid,
                    filtered_tasks.iter().map(|&task| task.clone()).collect(),
                );
            }

            if task_tid_list.insert(*tid) {
                let selected_parent_pid = if parsed_args.use_real_parent {
                    primary_task.real_ppid
                } else {
                    primary_task.ppid
                };

                if let Some(parent_pid) = selected_parent_pid
                    && parent_pid != primary_task.tgid
                {
                    tree_state
                        .children_map
                        .entry(parent_pid)
                        .or_default()
                        .push(*tid);
                }
            }
        }

        for &tid in &task_tid_list {
            let tasks = match task_map.get(&tid) {
                Some(tasks) => tasks,
                None => continue,
            };

            let primary_task = match tasks.first() {
                Some(task) => task,
                None => continue,
            };

            let selected_parent_pid = if parsed_args.use_real_parent {
                primary_task.real_ppid
            } else {
                primary_task.ppid
            };

            let is_root_task = selected_parent_pid
                .map(|parent_pid| {
                    parent_pid == primary_task.tgid || !task_tid_list.contains(&parent_pid)
                })
                .unwrap_or(true);

            if is_root_task {
                root_task_tid_list.push(tid);
            }
        }

        let parent_field = if parsed_args.use_real_parent {
            "task_struct::real_parent"
        } else {
            "task_struct::parent"
        };

        let threads_status = if parsed_args.show_threads {
            "Enabled"
        } else {
            "Disabled"
        };

        println!("Parent: {}", parent_field);
        println!("Threads: {}", threads_status);
        println!("Page Table: {page_table_address}\n");

        for (idx, &root_tid) in root_task_tid_list.iter().enumerate() {
            let is_last = idx == root_task_tid_list.len() - 1;
            Self::print_tree(&tree_state, root_tid, "", is_last, parsed_args.show_threads);
        }

        Ok(())
    }
}

impl Default for TaskTreeCommand {
    fn default() -> Self {
        Self::new()
    }
}
