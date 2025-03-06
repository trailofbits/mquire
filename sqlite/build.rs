//
// Copyright (c) 2025-present, Trail of Bits, Inc.
// All rights reserved.
//
// This source code is licensed in accordance with the terms specified in
// the LICENSE file found in the root directory of this source tree.
//

use std::{env, path::PathBuf};

fn main() {
    let bindings = bindgen::Builder::default()
        .header("library/sqlite3.h")
        .parse_callbacks(Box::new(bindgen::CargoCallbacks::new()))
        .generate()
        .expect("Unable to generate the sqlite bindings");

    let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());

    bindings
        .write_to_file(out_path.join("sqlite.rs"))
        .expect("Couldn't write the sqlite bindings");

    cc::Build::new()
        .file("library/sqlite3.c")
        .flag("-w")
        .compile("sqlite_native");
}
