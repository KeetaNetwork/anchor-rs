use utils::build::{compile_asn1_directory_with_full_config, Asn1CompileConfig};

fn main() {
	let config = Asn1CompileConfig::new("asn1", "src/generated")
		.with_generated_rs_path("src/lib/generated.rs")
		.with_remove_module_wrappers(true);

	if let Err(e) = compile_asn1_directory_with_full_config(&config) {
		panic!("ASN.1 compilation failed: {e}");
	}
}
