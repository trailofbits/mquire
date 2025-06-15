#!/usr/bin/env bash

main() {
  local cargo_toml_path="$1"
  if [[ ! -f "${cargo_toml_path}" ]]; then
      return 1
  fi

  local version=$(grep version "${cargo_toml_path}" | head -n 1 | cut -d '"' -f 2)
  if [[ -z "${version}" ]]; then
      return 1
  fi

  printf "${version}"
  return 0
}

main $@
exit $?
