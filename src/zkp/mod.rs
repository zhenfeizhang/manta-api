// Copyright 2019-2021 Manta Network.
// This file is part of pallet-manta-pay.
//
// pallet-manta-pay is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// pallet-manta-pay is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with pallet-manta-pay.  If not, see <http://www.gnu.org/licenses/>.

//! This module contains zkp implementations for manta-pay.

mod circuit;
mod gadget;
mod keys;
mod verifier;

pub use circuit::{ReclaimCircuit, TransferCircuit};
pub(crate) use gadget::*;
#[cfg(feature = "std")]
pub use keys::write_zkp_keys;
pub use keys::{RECLAIM_PK, TRANSFER_PK};

use crate::payload::*;
use ark_ff::ToConstraintField;
use ark_groth16::verify_proof;
use ark_serialize::CanonicalDeserialize;
use ark_std::vec::Vec;
use manta_asset::*;
use manta_crypto::*;
use manta_error::MantaError;

