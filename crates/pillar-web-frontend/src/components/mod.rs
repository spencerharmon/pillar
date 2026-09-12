//! The pillar console **component library** — reusable Yew primitives built on
//! the design-system styles in [`crate::styles`].
//!
//! Each primitive follows the crate's **pure-logic / `yew`-glue split**: the
//! sort/filter/paginate, chart geometry, diff, tree-flatten, form-validation,
//! and toast-queue logic are plain host-testable Rust functions (asserted by
//! `cargo test -p pillar-web-frontend` with no browser), and the
//! `yew::Component`/function components are thin rendering wrappers around them,
//! compiled only behind the default `yew` feature.
//!
//! The primitives — [`DataTable`], [`StatCard`], [`Chart`]/[`Sparkline`],
//! [`Badge`]/[`StatusPill`], [`Drawer`], [`Tabs`], [`Tree`], [`FormField`],
//! [`CodeBlock`]/[`DiffView`], and [`ToastStack`] — gate console Phases 3–5.
//! `obs_console.rs` is the first real consumer: its materialized-panel table is
//! rendered through [`DataTable`] (see [`crate::obs_console`]), so the library
//! is wired in, not merely built in isolation.

// Base primitives (Card/Button/Input/Dialog/Combobox + the security-key/login
// controls) — pre-existing, retained here.
pub mod base;
// New Phase 1 console primitives, each a pure-logic + yew-glue module.
pub mod badge;
pub mod chart;
pub mod code_block;
pub mod data_table;
pub mod drawer;
pub mod form;
pub mod secret_reveal;
pub mod stat_card;
pub mod tabs;
pub mod toast;
pub mod tree;

// Re-export the base component API at the module root so existing
// `components::Card` / `components::LoginPanel` call sites keep working.
#[cfg(feature = "yew")]
pub use base::{
    Button, ButtonProps, Card, CardProps, ComboOption, Combobox, ComboboxProps, Dialog,
    DialogProps, Input, InputProps, LoginPanel, SecurityKeyControls, SecurityKeyControlsProps,
};

// Pure-logic types (always available, host-testable) re-exported at the root.
pub use badge::Tone;
pub use chart::{ChartKind, Range, Viewport};
pub use code_block::{DiffKind, DiffLine};
pub use data_table::{Column, Row, SortDir};
pub use drawer::Side;
pub use form::FieldRule;
pub use secret_reveal::mask as mask_secret;
pub use stat_card::Trend;
pub use toast::{Level, Toast};
pub use tree::{FlatRow, TreeNode};

// Yew component re-exports at the root.
#[cfg(feature = "yew")]
pub use badge::{Badge, BadgeProps, StatusPill, StatusPillProps};
#[cfg(feature = "yew")]
pub use chart::{Chart, ChartProps, Sparkline, SparklineProps};
#[cfg(feature = "yew")]
pub use code_block::{CodeBlock, CodeBlockProps, DiffView, DiffViewProps};
#[cfg(feature = "yew")]
pub use data_table::{DataTable, DataTableProps};
#[cfg(feature = "yew")]
pub use drawer::{Drawer, DrawerProps};
#[cfg(feature = "yew")]
pub use form::{FormField, FormFieldProps};
#[cfg(feature = "yew")]
pub use form::{FieldSet, FieldSetProps};
#[cfg(feature = "yew")]
pub use secret_reveal::{SecretReveal, SecretRevealProps};
#[cfg(feature = "yew")]
pub use stat_card::{StatCard, StatCardProps};
#[cfg(feature = "yew")]
pub use tabs::{TabItem, Tabs, TabsProps};
#[cfg(feature = "yew")]
pub use toast::{use_toaster, ToastProvider, ToastStack, ToastStackProps, Toaster};
#[cfg(feature = "yew")]
pub use tree::{Tree, TreeProps};
