//! Cast placement, ported from Ghidra 12.1.3's `ActionSetCasts` and
//! `CastStrategyC`.
//!
//! A cast is a statement about the program: it says the value's type is not
//! what this context requires. Emitting one everywhere a type *might* differ
//! says nothing and hides the places where a real conversion happens. Ghidra
//! asks, per operand, what type the operation requires, and inserts a cast only
//! where C would not make the conversion itself.
//!
//! The conversions C performs silently are: any integer to any other integer,
//! including between signednesses and widths; anything scalar to `bool` in a
//! condition; and an array to a pointer to its element. Everything else —
//! integer to pointer, pointer to a different pointee, integer to float —
//! is a real conversion and is spelled.
//!
//! Source authority: `ActionSetCasts::castInput`, `castOutput`, and
//! `CastStrategyC::castStandard` in `coreaction.cc` and `cast.cc` at commit
//! `8b4c91d4d5bd1549622bfbade0df199585b98365`.

use crate::native::Type;

/// Whether converting `from` to `to` needs to be written down.
pub fn needs_cast(from: &Type, to: &Type) -> bool {
    if from == to {
        return false;
    }
    match (from, to) {
        // C converts between integer types implicitly. The declared type of
        // the destination already states the width and signedness, so casting
        // as well repeats it.
        (Type::Unsigned(_) | Type::Signed(_) | Type::Bool, Type::Unsigned(_) | Type::Signed(_)) => {
            false
        }
        // Any scalar tests as a condition without a cast.
        (Type::Unsigned(_) | Type::Signed(_) | Type::Pointer(_) | Type::Float(_), Type::Bool) => {
            false
        }
        // A pointer's target type is not observable from the value, so a
        // change of target is a real claim about the program.
        (Type::Pointer(left), Type::Pointer(right)) => left != right,
        // Anything unknown carries no claim, so converting it states nothing.
        (Type::Unknown, _) | (_, Type::Unknown) => false,
        _ => true,
    }
}

/// Whether an address expression needs the `(uintptr_t)` a memory access
/// otherwise carries.
///
/// A value already typed as a pointer is already an address; spelling the
/// conversion again is the `(uintptr_t)` noise that made every memory access in
/// the output three casts deep.
pub fn address_needs_cast(ty: &Type) -> bool {
    !matches!(ty, Type::Pointer(_))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identical_types_need_no_cast() {
        assert!(!needs_cast(&Type::Unsigned(32), &Type::Unsigned(32)));
    }

    #[test]
    fn integer_conversions_are_implicit() {
        assert!(!needs_cast(&Type::Unsigned(32), &Type::Signed(64)));
        assert!(!needs_cast(&Type::Signed(64), &Type::Unsigned(32)));
        assert!(!needs_cast(&Type::Unsigned(8), &Type::Unsigned(64)));
    }

    #[test]
    fn a_condition_accepts_any_scalar() {
        assert!(!needs_cast(&Type::Unsigned(32), &Type::Bool));
        assert!(!needs_cast(
            &Type::Pointer(Box::new(Type::Unsigned(8))),
            &Type::Bool
        ));
    }

    #[test]
    fn crossing_between_integers_and_pointers_is_spelled() {
        let pointer = Type::Pointer(Box::new(Type::Unsigned(32)));
        assert!(needs_cast(&Type::Unsigned(32), &pointer));
        assert!(needs_cast(&pointer, &Type::Unsigned(32)));
    }

    #[test]
    fn changing_what_a_pointer_points_at_is_spelled() {
        let bytes = Type::Pointer(Box::new(Type::Unsigned(8)));
        let words = Type::Pointer(Box::new(Type::Unsigned(32)));
        assert!(needs_cast(&bytes, &words));
        assert!(!needs_cast(&bytes, &bytes.clone()));
    }

    #[test]
    fn float_and_integer_conversions_are_spelled() {
        assert!(needs_cast(&Type::Unsigned(32), &Type::Float(32)));
        assert!(needs_cast(&Type::Float(64), &Type::Signed(32)));
    }

    #[test]
    fn an_unknown_type_makes_no_claim() {
        assert!(!needs_cast(&Type::Unknown, &Type::Unsigned(32)));
        assert!(!needs_cast(&Type::Unsigned(32), &Type::Unknown));
    }

    #[test]
    fn a_pointer_valued_address_is_already_an_address() {
        assert!(!address_needs_cast(&Type::Pointer(Box::new(
            Type::Unsigned(8)
        ))));
        assert!(address_needs_cast(&Type::Unsigned(32)));
    }
}
