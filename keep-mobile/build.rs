// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: AGPL-3.0-or-later

fn main() {
    uniffi::generate_scaffolding("src/keep_mobile.udl")
        .expect("failed to generate UniFFI scaffolding");
}
