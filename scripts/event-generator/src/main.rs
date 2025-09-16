// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use proc_macro2::TokenStream;
use quote::quote;
use s2n_events::{Output, OutputMode, OutputConfig, PublisherTarget, Result, parser, validation};

const INPUT_PATH: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../rust/s2n-tls-core/events/**/*.rs"
);
const OUTPUT_PATH: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../rust/s2n-tls-core/src/event"
);

fn main() -> Result<()> {
    let mut files = vec![];
    for path in glob::glob(INPUT_PATH)? {
        let path = path?;
        eprintln!("loading {}", path.canonicalize().unwrap().display());
        let file = std::fs::read_to_string(&path)?;
        files.push(parser::parse(&file, path).unwrap());
    }

    // make sure events are in a deterministic order
    files.sort_by(|a, b| a.path.as_os_str().cmp(b.path.as_os_str()));

    // validate the events
    validation::validate(&files);

    let root = std::path::Path::new(OUTPUT_PATH);
    let _ = std::fs::create_dir_all(root);
    let root = root.canonicalize()?;

    let mut output = Output {
        s2n_quic_core_path: quote!(s2n_quic_core),
        tracing_subscriber_def: quote!(
            /// Emits events with [`tracing`](https://docs.rs/tracing)
            #[derive(Clone, Debug)]
            pub struct Subscriber {
                root: tracing::Span,
            }

            impl Default for Subscriber {
                fn default() -> Self {
                    let root = tracing::span!(target: "tls_test", tracing::Level::DEBUG, "tls_test");

                    Self {
                        root,
                    }
                }
            }

            impl Subscriber {
                fn parent<M: crate::event::Meta>(&self, _meta: &M) -> Option<tracing::Id> {
                    self.root.id()
                }
            }
        ),
        crate_name: "s2n_tls_core",
        root,
        config: OutputConfig {
            mode: OutputMode::Mut,
            publisher: PublisherTarget::C,
        },
        ..Default::default()
    };

    output.generate(&files);

    Ok(())
}
