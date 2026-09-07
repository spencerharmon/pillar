//! `CodeBlock` / line-oriented diff view.
//!
//! The diff computation is **pure logic** ([`diff_lines`], [`DiffLine`]) — a
//! classic LCS line matcher producing an add/remove/context sequence — so it is
//! host-tested with no `yew` dependency. The Yew components render a plain code
//! block or the coloured diff around it. This feeds Phase 3's manifest-diff tab.

/// One line of a rendered diff.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DiffLine {
    /// The change kind.
    pub kind: DiffKind,
    /// The line text (without a trailing newline).
    pub text: String,
}

/// The kind of a [`DiffLine`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DiffKind {
    /// Present in both sides (unchanged).
    Context,
    /// Added on the new side.
    Add,
    /// Removed from the old side.
    Remove,
}

/// Compute a line-oriented diff of `old` → `new` using an LCS backtrace.
///
/// The result is the classic unified sequence: unchanged lines appear once as
/// [`DiffKind::Context`], removed lines as [`DiffKind::Remove`], added lines as
/// [`DiffKind::Add`]. Removals for a given position precede the additions.
#[must_use]
pub fn diff_lines(old: &str, new: &str) -> Vec<DiffLine> {
    let a: Vec<&str> = old.lines().collect();
    let b: Vec<&str> = new.lines().collect();
    let (n, m) = (a.len(), b.len());

    // LCS length table.
    let mut lcs = vec![vec![0usize; m + 1]; n + 1];
    for i in (0..n).rev() {
        for j in (0..m).rev() {
            lcs[i][j] = if a[i] == b[j] {
                lcs[i + 1][j + 1] + 1
            } else {
                lcs[i + 1][j].max(lcs[i][j + 1])
            };
        }
    }

    // Backtrace into a diff sequence.
    let mut out = Vec::new();
    let (mut i, mut j) = (0usize, 0usize);
    while i < n && j < m {
        if a[i] == b[j] {
            out.push(DiffLine {
                kind: DiffKind::Context,
                text: a[i].to_owned(),
            });
            i += 1;
            j += 1;
        } else if lcs[i + 1][j] >= lcs[i][j + 1] {
            out.push(DiffLine {
                kind: DiffKind::Remove,
                text: a[i].to_owned(),
            });
            i += 1;
        } else {
            out.push(DiffLine {
                kind: DiffKind::Add,
                text: b[j].to_owned(),
            });
            j += 1;
        }
    }
    while i < n {
        out.push(DiffLine {
            kind: DiffKind::Remove,
            text: a[i].to_owned(),
        });
        i += 1;
    }
    while j < m {
        out.push(DiffLine {
            kind: DiffKind::Add,
            text: b[j].to_owned(),
        });
        j += 1;
    }
    out
}

#[cfg(feature = "yew")]
pub use yew_impl::{CodeBlock, CodeBlockProps, DiffView, DiffViewProps};

#[cfg(feature = "yew")]
mod yew_impl {
    use super::{diff_lines, DiffKind};
    use yew::prelude::*;

    /// Props for [`CodeBlock`].
    #[derive(Properties, PartialEq)]
    pub struct CodeBlockProps {
        /// The code / text to render verbatim.
        pub code: AttrValue,
        /// Optional language hint (rendered as a `data-lang` attribute).
        #[prop_or_default]
        pub lang: AttrValue,
    }

    /// A monospaced, pre-formatted code block.
    #[function_component(CodeBlock)]
    pub fn code_block(props: &CodeBlockProps) -> Html {
        html! {
            <pre class="pillar-codeblock" data-lang={props.lang.clone()}>
                <code>{ props.code.clone() }</code>
            </pre>
        }
    }

    /// Props for [`DiffView`].
    #[derive(Properties, PartialEq)]
    pub struct DiffViewProps {
        /// The old (left) text.
        pub old: AttrValue,
        /// The new (right) text.
        pub new: AttrValue,
    }

    /// A line-oriented diff of `old` → `new`, coloured by [`DiffKind`].
    #[function_component(DiffView)]
    pub fn diff_view(props: &DiffViewProps) -> Html {
        let lines = diff_lines(props.old.as_str(), props.new.as_str());
        html! {
            <pre class="pillar-diff">
                { for lines.into_iter().map(|l| {
                    let (cls, sign) = match l.kind {
                        DiffKind::Context => ("pillar-diff__line is-context", " "),
                        DiffKind::Add => ("pillar-diff__line is-add", "+"),
                        DiffKind::Remove => ("pillar-diff__line is-remove", "-"),
                    };
                    html! {
                        <span class={cls}>{ format!("{sign} {}", l.text) }</span>
                    }
                }) }
            </pre>
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn kinds(d: &[DiffLine]) -> Vec<DiffKind> {
        d.iter().map(|l| l.kind).collect()
    }

    #[test]
    fn identical_input_is_all_context() {
        let d = diff_lines("a\nb\nc", "a\nb\nc");
        assert_eq!(kinds(&d), vec![DiffKind::Context; 3]);
        assert!(d.iter().all(|l| l.kind == DiffKind::Context));
    }

    #[test]
    fn added_line_shows_as_add_and_keeps_context() {
        let d = diff_lines("a\nc", "a\nb\nc");
        assert_eq!(
            kinds(&d),
            vec![DiffKind::Context, DiffKind::Add, DiffKind::Context]
        );
        assert_eq!(d[1].text, "b");
    }

    #[test]
    fn removed_line_shows_as_remove() {
        let d = diff_lines("a\nb\nc", "a\nc");
        assert_eq!(
            kinds(&d),
            vec![DiffKind::Context, DiffKind::Remove, DiffKind::Context]
        );
        assert_eq!(d[1].text, "b");
    }

    #[test]
    fn changed_line_is_a_remove_then_an_add() {
        let d = diff_lines("a\nold\nc", "a\nnew\nc");
        assert_eq!(
            kinds(&d),
            vec![
                DiffKind::Context,
                DiffKind::Remove,
                DiffKind::Add,
                DiffKind::Context
            ]
        );
        assert_eq!(d[1].text, "old");
        assert_eq!(d[2].text, "new");
    }

    #[test]
    fn from_empty_is_all_adds_and_to_empty_is_all_removes() {
        assert_eq!(kinds(&diff_lines("", "x\ny")), vec![DiffKind::Add; 2]);
        assert_eq!(kinds(&diff_lines("x\ny", "")), vec![DiffKind::Remove; 2]);
    }
}
