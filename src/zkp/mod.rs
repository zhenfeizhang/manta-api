// Copyright 2019-2021 Manta Network.
// This file is part of manta-api.
//
// manta-api is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// manta-api is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with manta-api.  If not, see <http://www.gnu.org/licenses/>.

//! This module contains zkp implementations for manta-pay.

mod circuit;
mod gadget;
#[cfg(feature = "std")]
mod keys;

pub use circuit::{ReclaimCircuit, TransferCircuit};
pub(crate) use gadget::*;
#[cfg(feature = "std")]
pub use keys::write_zkp_keys;

