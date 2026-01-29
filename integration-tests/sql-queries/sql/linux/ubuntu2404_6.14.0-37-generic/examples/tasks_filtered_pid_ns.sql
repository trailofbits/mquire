SELECT comm, binary_path, command_line FROM tasks WHERE source = 'pid_ns' AND command_line NOT NULL AND comm LIKE "%systemd%"
