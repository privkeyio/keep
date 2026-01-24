fn main() {
    uniffi::generate_scaffolding("src/keep_mobile.udl")
        .expect("failed to generate UniFFI scaffolding");
}
