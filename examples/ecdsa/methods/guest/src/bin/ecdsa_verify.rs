// Copyright 2024 RISC Zero, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use k256::{
    ecdsa::{signature::Verifier, Signature, VerifyingKey},
    EncodedPoint, schnorr,
};
use risc0_zkvm::guest::env;

fn main() {
    // Decode the verifying key, message, and signature from the inputs.
    let (encoded_verifying_key, schnorr_verifying_key, message, signature, schnorr_sig_bytes): (
        EncodedPoint,
        schnorr::VerifyingKey,
        Vec<u8>,
        Signature,
        Vec<u8>,
    ) = env::read();
    let verifying_key = VerifyingKey::from_encoded_point(&encoded_verifying_key).unwrap();

    let b = schnorr_sig_bytes.as_slice();
    let schnorr_sig = schnorr::Signature::try_from(b).unwrap();

    // Verify the signature, panicking if verification fails.
    verifying_key
        .verify(&message, &signature)
        .expect("ECDSA signature verification failed");

    schnorr_verifying_key
        .verify(&message, &schnorr_sig)
        .expect("schnorr verification failed");

    // Commit to the journal the verifying key and message that was signed.
    env::commit(&(encoded_verifying_key, schnorr_verifying_key, message ));
}
