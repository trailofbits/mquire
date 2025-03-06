//
// Copyright (c) 2025-present, Trail of Bits, Inc.
// All rights reserved.
//
// This source code is licensed in accordance with the terms specified in
// the LICENSE file found in the root directory of this source tree.
//

use crate::Result;
use std::collections::BTreeMap;

/// The type of a column in a table
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum ColumnType {
    /// A 64-bit signed integer
    SignedInteger,

    /// A 64-bit floating point number
    Double,

    /// A text string
    String,
}

/// The value of a column in a table
#[derive(Clone, Debug, PartialEq)]
pub enum ColumnValue {
    /// A 64-bit signed integer
    SignedInteger(i64),

    /// A 64-bit floating point number
    Double(f64),

    /// A text string
    String(String),
}

/// An optional `ColumnValue`
pub type OptionalColumnValue = Option<ColumnValue>;

/// A row in a table
pub type Row = BTreeMap<String, OptionalColumnValue>;

/// A list of rows in a table
pub type RowList = Vec<Row>;

/// A plugin that generates a table
pub trait TablePlugin {
    /// The schema of the table
    fn schema(&self) -> BTreeMap<String, ColumnType>;

    /// The name of the table
    fn name(&self) -> String;

    /// Generate the table rows
    fn generate(&self) -> Result<RowList>;
}
