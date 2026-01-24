//
// Copyright (c) 2025-present, Trail of Bits, Inc.
// All rights reserved.
//
// This source code is licensed in accordance with the terms specified in
// the LICENSE file found in the root directory of this source tree.
//

use crate::sqlite::error::Result;

use serde::Serialize;

use std::collections::BTreeMap;

/// The type of a column in a table
#[allow(dead_code)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum ColumnType {
    /// A 64-bit signed integer
    SignedInteger,

    /// A 64-bit floating point number
    Double,

    /// A text string
    String,
}

/// Column visibility in SELECT * queries
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub enum ColumnVisibility {
    /// Column is included in SELECT * (default)
    #[default]
    Visible,

    /// Column is hidden from SELECT * but explicitly selectable
    Hidden,
}

/// Column definition with type and visibility
#[derive(Clone, Debug)]
pub struct ColumnDef {
    /// The column type
    pub column_type: ColumnType,

    /// The column visibility
    pub visibility: ColumnVisibility,
}

impl ColumnDef {
    /// Creates a visible column definition
    pub fn visible(column_type: ColumnType) -> Self {
        Self {
            column_type,
            visibility: ColumnVisibility::Visible,
        }
    }

    /// Creates a hidden column definition
    pub fn hidden(column_type: ColumnType) -> Self {
        Self {
            column_type,
            visibility: ColumnVisibility::Hidden,
        }
    }
}

/// A constraint on a column used for generation hints
#[derive(Clone, Debug)]
pub struct Constraint {
    /// The column name
    pub column: String,

    /// The constraint value (equality only for now)
    pub value: ColumnValue,
}

/// Constraints passed to generate
pub type Constraints = Vec<Constraint>;

/// The value of a column in a table
#[derive(Clone, Debug, PartialEq, Serialize)]
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
    /// The table schema
    fn schema(&self) -> BTreeMap<String, ColumnDef>;

    /// The name of the table
    fn name(&self) -> String;

    /// Returns column names that serve as inputs to the generator (equality constraints only)
    fn generator_inputs(&self) -> Vec<String> {
        Vec::new()
    }

    /// Validates the constraints before generation
    fn validate_constraints(&self, _constraints: &Constraints) -> Result<()> {
        Ok(())
    }

    /// Generate the table rows
    fn generate(&self, constraints: &Constraints) -> Result<RowList>;
}
