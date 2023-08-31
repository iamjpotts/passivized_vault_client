
//! Define which Vault images the Rust library will be tested against.
//!
//! # Examples
//!
//! ```rust
//! use passivized_vault_client_versions::test_current_image;
//!
//! #[test_current_image]
//! fn test_foo(image_name: &str, image_tag: &str) {
//!     // ...test implementation to run against only the latest image
//! }
//! ```
//!
//! ```rust
//! use passivized_vault_client_versions::test_supported_images;
//!
//! #[test_supported_images]
//! fn test_bar(image_name: &str, image_tag: &str) {
//!     // ...test implementation to run against all supported images
//! }
//! ```

use proc_macro::TokenStream as CompilerTokenStream;
use quote::{quote, quote_spanned};

/// Docker images of Vault versions supported by this library, in ascending order.
fn supported() -> Vec<(String, String)> {
    let source = [
        "1.11.12",
        "1.12.10",
        "1.13.6",
        "1.14.2",
    ];

    source
        .into_iter()
        .map(|t| ("hashicorp/vault".into(), t.into()))
        .collect()
}

/// Docker image of most recent supported Vault version.
fn current() -> (String, String) {
    supported().into_iter().last().unwrap()
}

fn image_test_case(image_name: &str, image_tag: &str) -> proc_macro2::TokenStream {
    quote! {
        #[test_case::test_case(#image_name, #image_tag)]
    }
}

fn unexpected_meta(meta: CompilerTokenStream) -> Option<CompilerTokenStream> {
    let m2: proc_macro2::TokenStream = meta.into();

    if let Some(m) = m2.into_iter().next() {
        let result = quote_spanned! { m.span() =>
            compile_error!("Macro does not expect any arguments.");
        };

        Some(result.into())
    } else {
        None
    }
}

#[proc_macro_attribute]
pub fn test_current_image(
    meta: CompilerTokenStream,
    input: CompilerTokenStream,
) -> CompilerTokenStream {
    if let Some(err) = unexpected_meta(meta) {
        err
    } else {
        let (image_name, image_tag) = current();

        let tokens = vec![image_test_case(&image_name, &image_tag), input.into()];

        let result = quote! {
            #(#tokens)*
        };

        result.into()
    }
}

#[proc_macro_attribute]
pub fn test_supported_images(
    meta: CompilerTokenStream,
    input: CompilerTokenStream,
) -> CompilerTokenStream {
    if let Some(err) = unexpected_meta(meta) {
        err
    } else {
        let mut tokens: Vec<_> = supported()
            .iter()
            .map(|(image_name, image_tag)| {
                quote! {
                    #[test_case::test_case(#image_name, #image_tag)]
                }
            })
            .collect();

        tokens.push(input.into());

        let result = quote! {
            #(#tokens)*
        };

        result.into()
    }
}
