SELECT comm, binary_path, command_line FROM tasks WHERE source = 'task_list' AND command_line NOT NULL AND comm LIKE "%systemd%"
