use dep::aztec::{
    protocol_types::{
        address::AztecAddress, traits::Empty, constants::GENERATOR_INDEX__NOTE_NULLIFIER,
        hash::poseidon2_hash_with_separator
    },
    note::{note_header::NoteHeader, note_interface::NoteInterface, utils::compute_note_hash_for_nullify},
    oracle::unsafe_rand::unsafe_rand, keys::getters::get_nsk_app, context::PrivateContext
};

// Define global constants for note length and bytes length
const ADDRESS_NOTE_LEN: usize = 3;
const ADDRESS_NOTE_BYTES_LEN: usize = 3 * 32 + 64;

// Struct to represent an address note
#[aztec(note)]
struct AddressNote {
    address: AztecAddress,
    npk_m_hash: Field,
    randomness: Field,
    header: NoteHeader, // Ensure header is included
}

// Implement the NoteInterface for AddressNote
impl NoteInterface<ADDRESS_NOTE_LEN, ADDRESS_NOTE_BYTES_LEN> for AddressNote {

    fn compute_nullifier(self, context: &mut PrivateContext, note_hash_for_nullify: Field) -> Field {
        let secret = context.request_nsk_app(self.npk_m_hash);
        poseidon2_hash_with_separator(
            [
                note_hash_for_nullify,
                secret
            ],
            GENERATOR_INDEX__NOTE_NULLIFIER as Field
        )
    }

    fn compute_nullifier_without_context(self) -> Field {
        let note_hash_for_nullify = compute_note_hash_for_nullify(self);
        let secret = get_nsk_app(self.npk_m_hash);
        poseidon2_hash_with_separator(
            [
                note_hash_for_nullify,
                secret
            ],
            GENERATOR_INDEX__NOTE_NULLIFIER as Field
        )
    }
}

// Implementation of AddressNote with additional methods
impl AddressNote {
    pub fn new(address: AztecAddress, npk_m_hash: Field) -> Self {
        let randomness = unsafe_rand();
        AddressNote { 
            address, 
            npk_m_hash, 
            randomness,
            header: NoteHeader::empty() // Initialize the header as empty
        }
    }
}
