use vergen_gix::{Cargo, Emitter, Gix};

fn main() {
    println!("cargo:rerun-if-changed=build.rs");

    let git = Gix::all_git();
    let cargo = Cargo::all_cargo();
    let emitted = Emitter::default()
        .add_instructions(&git)
        .and_then(|emitter| emitter.add_instructions(&cargo))
        .and_then(|emitter| emitter.emit());
    if let Err(error) = emitted {
        // Building from a source archive without `.git` must still work.
        println!("cargo:warning=could not read build metadata: {error}");
    }
}
