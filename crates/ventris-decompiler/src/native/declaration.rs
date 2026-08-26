//! C declaration and function-prototype rendering.
//!
//! The implementation follows Ghidra 12.1.3's `PrintC` declaration helpers:
//! `emitPrototypeOutput` (printc.cc:2260), `emitPrototypeInputs`
//! (printc.cc:2288), `emitVarDecl` (printc.cc:2629),
//! `emitVarDeclStatement` (printc.cc:2642), `emitSymbolScope`
//! (printc.cc:233), and `emitFunctionDeclaration` (printc.cc:2709).
//!
//! Unlike the emitter stack used by Ghidra, these functions return source
//! fragments.  The caller supplies the function's local scope because entering
//! that scope is what lets Ghidra resolve `ProtoParameter::getSymbol()` while
//! `emitPrototypeInputs` is running.  The graph's parameter model identifies a
//! backing symbol by exact storage, so this module performs the corresponding
//! `Scope::find_addr` lookup and never guesses from a matching name.

use crate::graph::funcproto::{FuncProto, ProtoParameter};
use crate::graph::scope::{ScopeLocal, Symbol};
use crate::graph::typefactory::to_native;

use super::Type;

/// Render the output type emitted by `PrintC::emitPrototypeOutput`
/// (printc.cc:2260).
///
/// Ghidra also associates the first return op's input with the emitted type for
/// markup.  Markup has no source spelling in Ventris, so the prototype output
/// is exactly the C type text.
pub(super) fn render_prototype_output(proto: &FuncProto) -> String {
    render_type(proto.get_output_type())
}

/// Render the comma-separated inputs emitted by
/// `PrintC::emitPrototypeInputs` (printc.cc:2288).
///
/// `scope` is the function-local scope that Ghidra enters immediately before
/// this emitter.  A parameter first tries an exact `Location` lookup in that
/// scope.  If no backing symbol is present, its own recovered name is used when
/// one exists; an unnamed parameter is rendered as a type-only declaration,
/// matching Ghidra's null-`getSymbol()` branch.
///
/// `hide_thisparam` is the equivalent of PrintLanguage's `hide_thisparam`
/// modifier.  The normal C renderer passes `false`; language front ends that
/// hide an implicit receiver can pass `true`.
pub(super) fn render_prototype_inputs(
    proto: &FuncProto,
    scope: Option<&ScopeLocal>,
    hide_thisparam: bool,
) -> String {
    let parameter_count = proto.num_params();
    let mut rendered = String::new();

    if parameter_count == 0 {
        // This is deliberately `void`, not an empty pair of parentheses:
        // emitPrototypeInputs prints KEYWORD_VOID for an empty fixed list.
        rendered.push_str("void");
    } else {
        let mut print_comma = false;
        for index in 0..parameter_count {
            let Some(parameter) = proto.get_param(index) else {
                // `num_params` and `get_param` are backed by the same vector;
                // retaining this guard keeps the renderer total if that
                // representation ever changes.
                continue;
            };
            if hide_thisparam && parameter.is_this_pointer() {
                continue;
            }
            if print_comma {
                rendered.push_str(", ");
            }
            rendered.push_str(&render_parameter(parameter, scope));
            print_comma = true;
        }
    }

    if proto.is_dotdotdot() {
        // Ghidra keys this comma on the original parameter count rather than
        // on the number left after hide_thisparam filtering.  Preserve that
        // behavior for the unusual all-hidden-parameter case as well.
        if parameter_count != 0 {
            rendered.push_str(", ");
        }
        rendered.push_str("...");
    }

    rendered
}

/// Render a complete function declaration using the spelling of the current
/// native printer: return type, escaped name, and prototype inputs.
///
/// This deliberately omits the ABI model name.  `native::printer` currently
/// emits no calling-convention token, and this default therefore lets the
/// prototype-backed declaration replace its statement-derived signature
/// without changing unrelated source spelling.  Use
/// [`render_function_declaration_with_options`] when a caller wants Ghidra's
/// `option_convention` behavior.
pub(super) fn render_function_declaration(
    proto: &FuncProto,
    scope: Option<&ScopeLocal>,
    name: &str,
) -> String {
    render_function_declaration_with_options(proto, scope, name, false, false)
}

/// Render a function declaration with the two PrintC declaration modifiers
/// that affect its source spelling.
///
/// `hide_thisparam` controls the implicit receiver.  `include_convention`
/// corresponds to PrintC's `option_convention`; when enabled, the model name
/// is printed only if `FuncProto::print_model_in_decl()` permits it.
pub(super) fn render_function_declaration_with_options(
    proto: &FuncProto,
    scope: Option<&ScopeLocal>,
    name: &str,
    hide_thisparam: bool,
    include_convention: bool,
) -> String {
    let mut rendered = render_prototype_output(proto);
    rendered.push(' ');
    if include_convention && proto.print_model_in_decl() {
        rendered.push_str(proto.get_model_name());
        rendered.push(' ');
    }
    rendered.push_str(&escape_identifier(name));
    rendered.push('(');
    rendered.push_str(&render_prototype_inputs(proto, scope, hide_thisparam));
    rendered.push(')');
    rendered
}

/// Keep the `Option<FuncProto>` boundary honest for callers reading
/// `Funcdata::func_proto()`.
///
/// A missing prototype means that no calling convention or output/input
/// declaration exists.  It is not silently converted into a `void` function;
/// the caller receives `None` and must choose its architecture-specific
/// fallback, if one is appropriate.
pub(super) fn render_optional_function_declaration(
    proto: Option<&FuncProto>,
    scope: Option<&ScopeLocal>,
    name: &str,
) -> Option<String> {
    proto.map(|proto| render_function_declaration(proto, scope, name))
}

/// Render one formal variable declaration as emitted by `PrintC::emitVarDecl`
/// (printc.cc:2629).
///
/// `Symbol` stores the graph's rich `DataType`; lowering it through the same
/// native type boundary used by the rest of this crate preserves the current
/// printer's spelling (`uint32_t`, `uintptr_t`, `float`, and so on).
pub(super) fn render_var_decl(symbol: &Symbol) -> String {
    let ty = render_symbol_type(symbol);
    format!("{ty} {}", escape_identifier(symbol.display_name()))
}

fn render_parameter(parameter: &ProtoParameter, scope: Option<&ScopeLocal>) -> String {
    if let Some(symbol) = backing_symbol(parameter, scope) {
        return render_var_decl(symbol);
    }

    let ty = render_type(parameter.get_type());
    if parameter.is_name_undefined() {
        // This is Ghidra's explicit null-symbol fallback: push the type with
        // no identifier at all.
        ty
    } else {
        // Scope-less graph callers can still carry a recovered source name on
        // the prototype parameter.  Preserve that name without pretending a
        // symbol was found at a different storage location.
        format!("{ty} {}", escape_identifier(parameter.get_name()))
    }
}

fn backing_symbol<'a>(
    parameter: &ProtoParameter,
    scope: Option<&'a ScopeLocal>,
) -> Option<&'a Symbol> {
    let scope = scope?;
    // Storage is the parameter's identity.  In particular, do not search by
    // parameter name: two locals can share a name while occupying different
    // storage, and a name match would hide a prototype/scope disagreement.
    let entry = scope.find_addr(parameter.get_address(), 0)?;
    scope.entry_symbol(entry.id())
}

fn render_type(ty: &Type) -> String {
    ty.c_name().to_owned()
}

fn render_symbol_type(symbol: &Symbol) -> String {
    to_native(symbol.get_type()).c_name().to_owned()
}

// Keep this byte-for-byte equivalent to native/printer.rs's private helper.
fn escape_identifier(name: &str) -> String {
    let mut escaped = String::new();
    for (index, character) in name.chars().enumerate() {
        if (index == 0 && character.is_ascii_digit()) || !is_identifier_character(index, character)
        {
            escaped.push_str(&format!("_u{:x}_", u32::from(character)));
        } else {
            escaped.push(character);
        }
    }

    if escaped.is_empty() {
        escaped.push_str("_unnamed");
    }
    if is_c_keyword(&escaped) {
        escaped.insert(0, '_');
    }
    escaped
}

fn is_identifier_character(index: usize, character: char) -> bool {
    if index == 0 {
        character == '_' || character.is_ascii_alphabetic()
    } else {
        character == '_' || character.is_ascii_alphanumeric()
    }
}

fn is_c_keyword(identifier: &str) -> bool {
    matches!(
        identifier,
        "auto"
            | "break"
            | "case"
            | "char"
            | "const"
            | "continue"
            | "default"
            | "do"
            | "double"
            | "else"
            | "enum"
            | "extern"
            | "float"
            | "for"
            | "goto"
            | "if"
            | "inline"
            | "int"
            | "long"
            | "register"
            | "restrict"
            | "return"
            | "short"
            | "signed"
            | "sizeof"
            | "static"
            | "struct"
            | "switch"
            | "typedef"
            | "union"
            | "unsigned"
            | "void"
            | "volatile"
            | "while"
            | "_Alignas"
            | "_Alignof"
            | "_Atomic"
            | "_Bool"
            | "_Complex"
            | "_Generic"
            | "_Imaginary"
            | "_Noreturn"
            | "_Static_assert"
            | "_Thread_local"
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::graph::guard::Location;
    use ventris_lifter::REGISTER_SPACE;
    use ventris_target::{Abi, TargetProfile};

    fn location(offset: u64, size: u32) -> Location {
        Location {
            space: REGISTER_SPACE,
            offset,
            size,
        }
    }

    fn prototype() -> FuncProto {
        FuncProto::new(Abi::for_target(TargetProfile::GameCube))
    }

    fn mapped_scope(entries: &[(&str, Location, Type)]) -> ScopeLocal {
        let mut scope = ScopeLocal::new(REGISTER_SPACE);
        for (name, storage, ty) in entries {
            let symbol = scope.add_symbol(*name, ty.clone());
            assert!(scope.add_map_point(symbol, *storage).is_some());
        }
        scope
    }

    #[test]
    fn zero_parameter_prototype_renders_void() {
        let proto = prototype();
        assert_eq!(render_prototype_output(&proto), "void");
        assert_eq!(render_prototype_inputs(&proto, None, false), "void");
        assert_eq!(
            render_function_declaration(&proto, None, "nothing"),
            "void nothing(void)"
        );
    }

    #[test]
    fn parameters_use_scope_symbols_in_prototype_order() {
        let first = location(0x20, 4);
        let second = location(0x28, 8);
        let mut proto = prototype();
        proto.set_output_parts(location(0x40, 4), Type::Unsigned(32));
        // Deliberately use different prototype names: an exact storage match
        // must select the scope symbol's display name and type.
        proto.add_param_parts("recovered_first", first, Type::Signed(16));
        proto.add_param_parts("recovered_second", second, Type::Float(32));
        let scope = mapped_scope(&[
            ("count", first, Type::Unsigned(32)),
            ("ratio", second, Type::Float(64)),
        ]);

        assert_eq!(
            render_prototype_inputs(&proto, Some(&scope), false),
            "uint32_t count, double ratio"
        );
        assert_eq!(
            render_function_declaration(&proto, Some(&scope), "ordered"),
            "uint32_t ordered(uint32_t count, double ratio)"
        );
    }

    #[test]
    fn varargs_append_ellipsis_after_fixed_parameters() {
        let storage = location(0x20, 4);
        let mut proto = prototype();
        proto.add_param_parts("value", storage, Type::Unsigned(32));
        proto.set_dotdotdot(true);
        let scope = mapped_scope(&[("value", storage, Type::Unsigned(32))]);

        assert_eq!(
            render_prototype_inputs(&proto, Some(&scope), false),
            "uint32_t value, ..."
        );
    }

    #[test]
    fn unnamed_parameter_without_backing_symbol_is_type_only() {
        let mut proto = prototype();
        proto.add_param_parts("", location(0x20, 2), Type::Signed(16));

        assert_eq!(render_prototype_inputs(&proto, None, false), "int16_t");
    }

    #[test]
    fn scope_lookup_requires_exact_storage_before_name_fallback() {
        let parameter_storage = location(0x20, 4);
        let other_storage = location(0x28, 4);
        let mut proto = prototype();
        proto.add_param_parts("same_name", parameter_storage, Type::Unsigned(32));
        let scope = mapped_scope(&[("same_name", other_storage, Type::Float(64))]);

        assert_eq!(
            render_prototype_inputs(&proto, Some(&scope), false),
            "uint32_t same_name"
        );
    }

    #[test]
    fn hidden_this_parameter_is_skipped_without_reordering_the_rest() {
        let this_storage = location(0x20, 4);
        let value_storage = location(0x28, 4);
        let mut proto = prototype();
        proto.add_param_parts("self", this_storage, Type::Pointer(Box::new(Type::Void)));
        proto.add_param_parts("value", value_storage, Type::Unsigned(32));
        proto.get_param_mut(0).unwrap().set_this_pointer(true);
        let scope = mapped_scope(&[
            ("self", this_storage, Type::Pointer(Box::new(Type::Void))),
            ("value", value_storage, Type::Unsigned(32)),
        ]);

        assert_eq!(
            render_prototype_inputs(&proto, Some(&scope), true),
            "uint32_t value"
        );
    }

    #[test]
    fn missing_prototype_is_not_invented_as_void() {
        assert_eq!(
            render_optional_function_declaration(None, None, "unknown"),
            None
        );
    }
}
