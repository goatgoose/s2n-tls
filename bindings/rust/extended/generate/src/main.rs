// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::{
    collections::BTreeSet,
    fs::{self, read_to_string},
    io,
    path::Path,
    sync::{Arc, Mutex},
};

use bindgen::callbacks::ItemKind;

/// This is a placeholder that is replaced with the appropriate "feature token".
/// The placeholder is found in the *.template files of s2n-tls-sys/templates.
/// In Cargo.template this is replaced with the autogenerated list of features,
/// and in features.template this is replaced with the autogenerated list of
/// modules.
const FEATURE_TOKEN_PLACEHOLDER: &str = "<TOKEN_REPLACED_WITH_UNSTABLE_FEATURES>";

/// This binary is only expected to run in the context of the generate.sh script
/// which handles certain behaviors such as copying header files to
/// s2n-tls-sys/lib and other sundry actions.
fn main() {
    let out_dir = std::env::args().nth(1).expect("missing sys dir");
    let out_dir = Path::new(&out_dir);

    let functions = FunctionCallbacks::default();

    gen_bindings(
        "#include <s2n.h>",
        &out_dir.join("lib"),
        functions.with_feature(None),
    )
    .allowlist_type("s2n_.*")
    .allowlist_function("s2n_.*")
    .allowlist_var("s2n_.*")
    .generate()
    .unwrap()
    .write_to_file(out_dir.join("src/api.rs"))
    .unwrap();

    write_feature_bindings(
        out_dir.join("lib/tls/s2n_internal.h"),
        "internal",
        out_dir,
        out_dir.join("src/features/internal.rs"),
        functions.clone(),
    );
    write_feature_bindings(
        out_dir.join("lib/tls/s2n_quic_support.h"),
        "quic",
        out_dir,
        out_dir.join("src/features/quic.rs"),
        functions.clone(),
    );

    // get all of the files in the unstable folder
    let unstable_api = out_dir.join("lib/api/unstable");
    let unstable_headers: Vec<(String, fs::DirEntry)> = fs::read_dir(unstable_api)
        .expect("unable to iterate through files in unstable api folder")
        .into_iter()
        .map(|dir_entry| dir_entry.expect("failed to read header"))
        .map(|dir_entry| {
            (
                dir_entry
                    .path()
                    .file_stem()
                    .unwrap()
                    .to_str()
                    .unwrap()
                    .to_owned(),
                dir_entry,
            )
        })
        .collect();

    // write unstable bindings for them
    for (header_name, header) in unstable_headers.iter() {
        let feature_name = format!("unstable-{}", header_name);
        write_feature_bindings(
            header.path(),
            &feature_name,
            out_dir,
            out_dir.join(format!("src/features/{}.rs", header_name)),
            functions.clone(),
        );
    }

    // generate a cargo.toml that defines the correct features
    let mut features_definition_token = unstable_headers
        .iter()
        .map(|(header_name, _header)| format!("unstable-{header_name} = []"))
        .collect::<Vec<String>>();
    features_definition_token.sort();
    let cargo_template = out_dir.join("templates/Cargo.template");
    let cargo_template = read_to_string(cargo_template).expect("unable to read cargo template");
    let cargo_toml = cargo_template.replace(FEATURE_TOKEN_PLACEHOLDER, &(features_definition_token.join("\n")));
    fs::write(out_dir.join("Cargo.toml"), cargo_toml).unwrap();

    // generate a features.rs that includes the correct modules
    let features_module_token = unstable_headers
        .iter()
        .map(|(header_name, _header)| {
            format!("conditional_module!({header_name}, \"unstable-{header_name}\");")
        })
        .collect::<Vec<String>>()
        .join("\n");
    let features_template = out_dir.join("templates/features.template");
    let features_template = read_to_string(features_template).expect("unable to features template");
    let features_rs = features_template.replace(FEATURE_TOKEN_PLACEHOLDER, &features_module_token);
    std::fs::write(out_dir.join("src/features.rs"), features_rs).unwrap();

    functions.tests(&out_dir.join("src/tests.rs")).unwrap();

    gen_files(&out_dir.join("lib"), &out_dir.join("files.rs")).unwrap();
}

const COPYRIGHT: &str = r#"
// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
"#;

const PRELUDE: &str = r#"
#![allow(unused_imports, non_camel_case_types)]

use libc::{iovec, FILE, off_t};
// specify that aws-lc-rs is used, so that the rust compiler will link in the appropriate
// libcrypto artifact.
#[cfg(not(s2n_tls_external_build))]
extern crate aws_lc_rs as _;
"#;

fn base_builder() -> bindgen::Builder {
    bindgen::Builder::default()
        .use_core()
        .layout_tests(true)
        .detect_include_paths(true)
        .size_t_is_usize(true)
        .enable_function_attribute_detection()
        .default_enum_style(bindgen::EnumVariation::ModuleConsts)
        .rust_target(bindgen::RustTarget::Stable_1_47)
        // rust can't access thread-local variables
        // https://github.com/rust-lang/rust/issues/29594
        .blocklist_item("s2n_errno")
        .raw_line(COPYRIGHT)
        .raw_line(PRELUDE)
        .ctypes_prefix("::libc")
}

fn gen_bindings(entry: &str, s2n_dir: &Path, functions: FunctionCallbacks) -> bindgen::Builder {
    base_builder()
        .header_contents("s2n-sys.h", entry)
        // only export s2n-related stuff
        .blocklist_type("iovec")
        .blocklist_type("FILE")
        .blocklist_type("_IO_.*")
        .blocklist_type("__.*")
        .blocklist_type("fpos_t")
        .parse_callbacks(Box::new(functions))
        .clang_arg(format!("-I{}/api", s2n_dir.display()))
        .clang_arg(format!("-I{}", s2n_dir.display()))
}

fn write_feature_bindings(
    header_path: impl AsRef<Path>,
    feature_flag: &str,
    s2n_tls_sys_dir: &Path,
    output_path: impl AsRef<Path>,
    functions: FunctionCallbacks,
) {
    let header_path_str = format!("{}", header_path.as_ref().display());
    let lib_path = s2n_tls_sys_dir.join("lib");
    base_builder()
        .header(&header_path_str)
        .parse_callbacks(Box::new(
            functions.with_feature(Some(feature_flag.to_owned())),
        ))
        // manually include header contents
        .clang_arg(format!("-I{}/api", lib_path.display()))
        .clang_arg(format!("-I{}", lib_path.display()))
        .allowlist_recursively(false)
        .allowlist_file(&header_path_str)
        // s2n_internal.h defines opaque handles to these structs, but we want
        // them to be imported from the main api module
        .blocklist_type("s2n_connection")
        .blocklist_type("s2n_config")
        .raw_line("use crate::api::*;\n")
        .generate()
        .unwrap()
        .write_to_file(output_path)
        .unwrap();
}

fn gen_files(input: &Path, out: &Path) -> io::Result<()> {
    use io::Write;

    let mut files = std::fs::File::create(out)?;
    let mut o = io::BufWriter::new(&mut files);

    let pattern = format!("{}/**/*.c", input.display());

    writeln!(o, "{}", COPYRIGHT)?;
    writeln!(o, "[")?;
    for file in glob::glob(&pattern).unwrap() {
        let file = file.unwrap();
        let file = file.strip_prefix(input).unwrap();
        // don't include tests
        if file.starts_with("tests") {
            continue;
        }
        writeln!(o, "    {:?},", Path::new("lib").join(file).display())?;
    }
    writeln!(o, "]")?;
    Ok(())
}

type SharedBTreeSet<T> = Arc<Mutex<BTreeSet<T>>>;

#[derive(Clone, Debug, Default)]
struct FunctionCallbacks {
    /// the current feature that is having bindings generated
    feature: Arc<Mutex<Option<String>>>,
    /// a list of all functions that have had bindings generated for them
    functions: SharedBTreeSet<(Option<String>, String)>,
}

impl FunctionCallbacks {
    fn with_feature(&self, feature: Option<String>) -> Self {
        *self.feature.lock().unwrap() = feature;
        self.clone()
    }

    fn tests(&self, out: &Path) -> io::Result<()> {
        use io::Write;
        let functions = self.functions.lock().unwrap();
        let mut tests = std::fs::File::create(out)?;
        let mut o = io::BufWriter::new(&mut tests);

        writeln!(o, "{}", COPYRIGHT)?;
        let iter = functions.iter();
        for (feature, function) in iter {
            // don't generate a test if it's enabled without a feature
            if feature.is_some() && functions.contains(&(None, function.to_string())) {
                continue;
            }

            writeln!(o, "#[test]")?;

            // if the function is behind a feature, gate it with `cfg`
            if let Some(feature) = feature {
                writeln!(o, "#[cfg(feature = {:?})]", feature)?;
            };

            writeln!(o, "fn {} () {{", function)?;
            writeln!(o, "    let ptr = crate::{} as *const ();", function)?;
            writeln!(o, "    assert!(!ptr.is_null());")?;
            writeln!(o, "}}")?;
            writeln!(o)?;
        }

        Ok(())
    }
}

impl bindgen::callbacks::ParseCallbacks for FunctionCallbacks {
    fn enum_variant_name(
        &self,
        _name: Option<&str>,
        variant_name: &str,
        _variant_value: bindgen::callbacks::EnumVariantValue,
    ) -> Option<String> {
        if !variant_name.starts_with("S2N_") {
            return None;
        }

        let variant_name = variant_name
            .trim_start_matches("S2N_ERR_T_")
            .trim_start_matches("S2N_EXTENSION_")
            // keep the LEN_ so it's a valid identifier
            .trim_start_matches("S2N_TLS_MAX_FRAG_")
            .trim_start_matches("S2N_ALERT_")
            .trim_start_matches("S2N_CT_SUPPORT_")
            .trim_start_matches("S2N_STATUS_REQUEST_")
            .trim_start_matches("S2N_CERT_AUTH_")
            .trim_start_matches("S2N_CLIENT_HELLO_CB_")
            .trim_start_matches("S2N_TLS_SIGNATURE_")
            .trim_start_matches("S2N_TLS_HASH_")
            .trim_start_matches("S2N_PSK_HMAC_")
            .trim_start_matches("S2N_PSK_MODE_")
            .trim_start_matches("S2N_ASYNC_PKEY_VALIDATION_")
            .trim_start_matches("S2N_ASYNC_")
            .trim_start_matches("S2N_EARLY_DATA_STATUS_")
            // match everything else
            .trim_start_matches("S2N_");

        Some(variant_name.to_owned())
    }

    /// This doesn't actually rename anything, and is just used to get a list of
    /// all the functions that we generate bindings for, which is used for test
    /// generation later in the process.
    fn generated_name_override(
        &self,
        item_info: bindgen::callbacks::ItemInfo<'_>,
    ) -> Option<String> {
        if !item_info.name.starts_with("s2n_") {
            return None;
        }

        if let ItemKind::Function = item_info.kind {
            let feature = self.feature.lock().unwrap().clone();
            self.functions
                .lock()
                .unwrap()
                .insert((feature, item_info.name.to_owned()));
        }
        None
    }
}
