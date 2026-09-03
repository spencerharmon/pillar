//! The `pillar` web portal foundation — a Yew (client-side-rendered) single
//! page application styled with `stylist` (CSS-in-Rust). This is the P0
//! FOUNDATION: it establishes the Yew + WebAssembly + stylist build so later
//! portal work has a place to land. `trunk` compiles this crate to
//! `wasm32-unknown-unknown`, runs `wasm-bindgen` to emit the JS glue, and
//! bundles the stylist-emitted CSS — producing the wasm/js/css static assets a
//! two-stage nix build embeds into the one `pillar` binary. No npm/Node is
//! involved at any stage.

use stylist::yew::styled_component;
use yew::prelude::*;

/// The root portal component. A minimal, self-contained landing view proving
/// the Yew render + stylist styling path end to end; real portal tiles land on
/// top of this foundation in later tasks.
#[styled_component(App)]
pub fn app() -> Html {
    let container = css!(
        r#"
        font-family: system-ui, sans-serif;
        max-width: 40rem;
        margin: 4rem auto;
        padding: 0 1rem;
        color: #1a1a2e;
        "#
    );
    let heading = css!(
        r#"
        font-size: 1.75rem;
        font-weight: 700;
        "#
    );
    html! {
        <main class={container}>
            <h1 class={heading}>{ "pillar portal" }</h1>
            <p>{ "Yew + WebAssembly foundation is live." }</p>
        </main>
    }
}

/// The wasm entrypoint `trunk`/`wasm-bindgen` invokes on load: mount the Yew
/// app to the document body.
#[cfg(target_arch = "wasm32")]
#[wasm_bindgen::prelude::wasm_bindgen(start)]
pub fn start() {
    yew::Renderer::<App>::new().render();
}
