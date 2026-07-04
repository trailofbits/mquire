-- Registered ftrace callbacks whose target lands in neither the kernel text nor
-- any module listed in `kernel_modules`.
CREATE VIEW IF NOT EXISTS unbacked_ftrace_ops AS
SELECT
  h.virtual_address AS ops_address,
  h.func,
  h.func_addr,
  h.flags
FROM ftrace_ops h
WHERE h.func_addr NOT BETWEEN
        expect(
          (SELECT raw_vaddr(virtual_address) FROM kallsyms WHERE symbol_name = '_stext'),
          'unbacked_ftrace_ops: could not resolve kallsyms symbol _stext (kallsyms unavailable or stripped)'
        )
    AND expect(
          (SELECT raw_vaddr(virtual_address) FROM kallsyms WHERE symbol_name = '_etext'),
          'unbacked_ftrace_ops: could not resolve kallsyms symbol _etext (kallsyms unavailable or stripped)'
        )
  AND NOT EXISTS (
    SELECT 1
    FROM kernel_modules m
    JOIN kernel_module_mem_entries r ON r.kernel_module = m.virtual_address
    WHERE m.name != ''
      AND r.mem_type IN ('text', 'init_text')
      AND h.func_addr >= r.start
      AND h.func_addr < r.end
  )
ORDER BY h.func_addr, h.virtual_address;
