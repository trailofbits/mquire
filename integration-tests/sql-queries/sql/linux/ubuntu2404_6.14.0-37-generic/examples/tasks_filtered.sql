SELECT comm, binary_path, command_line FROM tasks WHERE command_line NOT NULL AND comm LIKE "%systemd%"
