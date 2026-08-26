//! Function prototypes and parameter storage, ported from Ghidra 12.1.3's
//! `ProtoParameter` and `FuncProto` in `fspec.hh`/`fspec.cc`.
//!
//! `Abi` is the static calling-convention part of Ghidra's `ProtoModel`.
//! Unlike [`crate::native::NativeCallPrototype`], this module keeps the
//! storage [`Location`] of every parameter alongside its recovered type and
//! source name.  The ABI does not contain address-space offsets, so model
//! storage locations are supplied by the graph/lifter adapter through
//! [`FuncProto::set_model_storage`].
//!
//! The twelve consumers in the matching decompiler read the following
//! surface:
//!
//! * `ActionConstbase` reads `get_inject_upon_entry`.
//! * `ActionDefaultParams` reads model presence/identity and uses
//!   `copy_from`/`set_internal`/`set_model`.
//! * `ActionDirectWrite` reads `possible_input_param`.
//! * `ActionExtraPopSetup` reads `get_extra_pop`.
//! * `ActionInputPrototype` reads the input lock, model derivation,
//!   `possible_input_param`, and input update methods.
//! * `ActionInternalStorage` iterates `internal_storage`.
//! * `ActionNormalizeSetup` clears input and releases model/output locks.
//! * `ActionOutputPrototype` reads the output parameter and output update
//!   methods.
//! * `ActionPrototypeTypes` reads model/input/output locks, `has_this_pointer`,
//!   parameters, and `assumed_input_extension`.
//! * `ActionPrototypeWarnings` reads the model/error/lock properties; the
//!   `emit_warnings` helper sends those diagnostics to `Funcdata::warning`.
//! * `ActionUnjustifiedParams` reads `unjustified_input_param`.
//! * `RulePiecePathology` reads input/output locks and updates
//!   `set_return_bytes_consumed`.
//!
//! Ghidra's model also has per-range effect records (including
//! `killedbycall`) and a `likelytrash` register list.  [`Abi`] has neither
//! concept, and this module deliberately does not invent them: call effects
//! remain represented by `graph::guard::CallEffects` and the target ABI's
//! caller/callee-saved sets.  The missing model metadata is reported explicitly
//! in this module documentation rather than represented by an always-false
//! placeholder.

use ventris_pcode::op;
use ventris_target::Abi;

use super::Funcdata;
use super::callproto::{ParamActive, TrialState};
use super::guard::Location;
use crate::native::Type;

/// The sentinel used by Ghidra for an unknown stack-pointer adjustment.
pub const EXTRAPOP_UNKNOWN: i32 = 0x8000;

/// How a storage range relates to a model parameter entry.
///
/// These values correspond to `ParamEntry::no_containment`,
/// `contains_unjustified`, `contains_justified`, and `contained_by` in
/// `fspec.hh`.  A range is justified when it starts at the least-significant
/// part of a parameter container for the configured byte order.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Containment {
    NoContainment = 0,
    ContainsUnjustified = 1,
    ContainsJustified = 2,
    ContainedBy = 3,
}

impl Containment {
    pub const fn as_u8(self) -> u8 {
        self as u8
    }
}

/// A function parameter viewed as a name, type, and storage location.
///
/// This is the graph-owned equivalent of Ghidra's `ParameterBasic`.  Lock
/// state is kept on the parameter rather than inferred from the type: an
/// unknown type can still have a locked storage size, which is exactly the
/// distinction needed by `ActionOutputPrototype` and
/// `ActionPrototypeTypes`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProtoParameter {
    /// Source-level name.  An empty name means that no name was recovered.
    pub name: String,
    /// Register/stack storage occupied by this parameter.
    pub location: Location,
    /// Recovered or declared type.
    pub ty: Type,
    type_locked: bool,
    name_locked: bool,
    size_type_locked: bool,
    this_pointer: bool,
    indirect_storage: bool,
    hidden_return: bool,
}

impl ProtoParameter {
    /// Construct an unlocked parameter from its complete storage description.
    pub fn new<N: Into<String>>(name: N, location: Location, ty: Type) -> Self {
        Self {
            name: name.into(),
            location,
            ty,
            type_locked: false,
            name_locked: false,
            size_type_locked: false,
            this_pointer: false,
            indirect_storage: false,
            hidden_return: false,
        }
    }

    /// Construct Ghidra's void return-value description.
    pub const fn void() -> Self {
        Self {
            name: String::new(),
            location: Location {
                space: 0,
                offset: 0,
                size: 0,
            },
            ty: Type::Void,
            type_locked: false,
            name_locked: false,
            size_type_locked: false,
            this_pointer: false,
            indirect_storage: false,
            hidden_return: false,
        }
    }

    /// `ProtoParameter::getName`.
    pub fn get_name(&self) -> &str {
        &self.name
    }

    /// `ProtoParameter::getType`.
    pub fn get_type(&self) -> &Type {
        &self.ty
    }

    /// `ProtoParameter::getAddress`.
    pub const fn get_address(&self) -> Location {
        self.location
    }

    /// `ProtoParameter::getSize`.
    pub const fn get_size(&self) -> u32 {
        self.location.size
    }

    /// `ProtoParameter::isTypeLocked`.
    pub const fn is_type_locked(&self) -> bool {
        self.type_locked
    }

    /// `ProtoParameter::isNameLocked`.
    pub const fn is_name_locked(&self) -> bool {
        self.name_locked
    }

    /// `ProtoParameter::isSizeTypeLocked`.
    pub const fn is_size_type_locked(&self) -> bool {
        self.size_type_locked
    }

    /// `ProtoParameter::isThisPointer`.
    pub const fn is_this_pointer(&self) -> bool {
        self.this_pointer
    }

    /// `ProtoParameter::isIndirectStorage`.
    pub const fn is_indirect_storage(&self) -> bool {
        self.indirect_storage
    }

    /// `ProtoParameter::isHiddenReturn`.
    pub const fn is_hidden_return(&self) -> bool {
        self.hidden_return
    }

    /// `ProtoParameter::isNameUndefined`.
    pub fn is_name_undefined(&self) -> bool {
        self.name.is_empty()
    }

    /// `ProtoParameter::setTypeLock`.
    ///
    /// Ghidra treats an unknown type specially: locking it also locks its
    /// storage size.  Unlocking clears both locks.
    pub fn set_type_lock(&mut self, value: bool) {
        self.type_locked = value;
        if value {
            if matches!(self.ty, Type::Unknown) {
                self.size_type_locked = true;
            }
        } else {
            self.size_type_locked = false;
        }
    }

    /// Set only the size lock.  This is useful when importing a locked ABI
    /// slot whose eventual signedness/type is not yet known.
    pub fn set_size_type_lock(&mut self, value: bool) {
        self.size_type_locked = value;
        if value {
            self.type_locked = true;
        }
    }

    /// `ProtoParameter::setNameLock`.
    pub const fn set_name_lock(&mut self, value: bool) {
        self.name_locked = value;
    }

    /// `ProtoParameter::setThisPointer`.
    pub const fn set_this_pointer(&mut self, value: bool) {
        self.this_pointer = value;
    }

    /// Set the hidden-return marker used by model-assigned storage.
    pub const fn set_hidden_return(&mut self, value: bool) {
        self.hidden_return = value;
    }

    /// Set the indirect-storage marker used by model-assigned storage.
    pub const fn set_indirect_storage(&mut self, value: bool) {
        self.indirect_storage = value;
    }

    /// Replace a size-locked unknown type without changing its storage size.
    ///
    /// This is `ParameterBasic::overrideSizeLockType`.  The operation fails
    /// rather than changing an unlocked or differently sized parameter, so a
    /// caller cannot accidentally discard a prototype lock.
    pub fn override_size_lock_type(&mut self, ty: Type) -> bool {
        if !self.size_type_locked || type_size(&ty, self.location.size) != self.location.size {
            return false;
        }
        self.ty = ty;
        true
    }

    /// Clear the type while preserving a size lock.
    ///
    /// This is `ParameterBasic::resetSizeLockType`; it is also useful to
    /// release an output's inferred type while retaining its ABI container.
    pub fn reset_size_lock_type(&mut self) -> bool {
        if matches!(self.ty, Type::Unknown) {
            return false;
        }
        self.ty = Type::Unknown;
        true
    }
}

/// A function prototype layered over one target [`Abi`].
///
/// `Abi` supplies static register classes, caller/callee preservation, stack
/// arguments, and return registers.  `FuncProto` adds function-specific
/// parameter descriptions, locks, flags, and recovery hints.  Since `Abi`
/// intentionally stores register *names* rather than architecture-specific
/// p-code offsets, callers that have an address-space map must supply explicit
/// model locations with [`set_model_storage`](Self::set_model_storage).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FuncProto {
    abi: Abi,
    model_extra_pop: i32,
    extra_pop: i32,
    model_input_locations: Vec<Location>,
    model_output_locations: Vec<Location>,
    params: Vec<ProtoParameter>,
    output: ProtoParameter,
    input_locked: bool,
    model_locked: bool,
    dotdotdot: bool,
    inline: bool,
    no_return: bool,
    has_this_pointer: bool,
    constructor: bool,
    destructor: bool,
    override_callsite: bool,
    custom_storage: bool,
    model_unknown: bool,
    print_model_in_decl: bool,
    input_errors: bool,
    output_errors: bool,
    inject_id: i32,
    inject_upon_entry: i32,
    inject_upon_return: i32,
    return_bytes_consumed: u32,
    big_endian: bool,
    internal_storage: Vec<Location>,
}

impl FuncProto {
    /// Construct a prototype backed by `abi`, with no recovered parameters.
    pub fn new(abi: Abi) -> Self {
        Self {
            abi,
            model_extra_pop: EXTRAPOP_UNKNOWN,
            extra_pop: EXTRAPOP_UNKNOWN,
            model_input_locations: Vec::new(),
            model_output_locations: Vec::new(),
            params: Vec::new(),
            output: ProtoParameter::void(),
            input_locked: false,
            model_locked: false,
            dotdotdot: false,
            inline: false,
            no_return: false,
            has_this_pointer: false,
            constructor: false,
            destructor: false,
            override_callsite: false,
            custom_storage: false,
            model_unknown: false,
            print_model_in_decl: true,
            input_errors: false,
            output_errors: false,
            inject_id: -1,
            inject_upon_entry: -1,
            inject_upon_return: -1,
            return_bytes_consumed: 0,
            big_endian: false,
            internal_storage: Vec::new(),
        }
    }

    /// Construct a prototype and configure the model's concrete storage list.
    pub fn with_storage(
        abi: Abi,
        input_locations: Vec<Location>,
        output_locations: Vec<Location>,
    ) -> Self {
        let mut result = Self::new(abi);
        result.set_model_storage(input_locations, output_locations);
        result
    }

    /// Return the static calling convention represented by this prototype.
    pub const fn abi(&self) -> Abi {
        self.abi
    }

    /// Replace the static model.
    ///
    /// Model storage is cleared because locations from the old convention are
    /// not valid for the new one.  Function-specific parameter descriptions and
    /// locks are intentionally retained, matching `FuncProto::setModel`.
    pub fn set_model(&mut self, abi: Abi) {
        self.abi = abi;
        self.model_input_locations.clear();
        self.model_output_locations.clear();
        self.model_extra_pop = EXTRAPOP_UNKNOWN;
        if self.extra_pop == self.model_extra_pop {
            self.extra_pop = EXTRAPOP_UNKNOWN;
        }
    }

    /// `FuncProto::hasModel`.
    pub const fn has_model(&self) -> bool {
        true
    }

    /// `FuncProto::hasMatchingModel`.
    pub fn has_matching_model(&self, abi: &Abi) -> bool {
        &self.abi == abi
    }

    /// `FuncProto::getModelName`.
    pub const fn get_model_name(&self) -> &'static str {
        self.abi.name
    }

    /// `FuncProto::getModelExtraPop`.
    pub const fn get_model_extra_pop(&self) -> i32 {
        self.model_extra_pop
    }

    /// Set the model's extrapop value.  [`set_extra_pop`](Self::set_extra_pop)
    /// remains the function-specific override read by call setup.
    pub const fn set_model_extra_pop(&mut self, value: i32) {
        self.model_extra_pop = value;
    }

    /// `FuncProto::isModelUnknown`.
    pub const fn is_model_unknown(&self) -> bool {
        self.model_unknown
    }

    /// Mark this prototype as using an unrecognized model name.
    pub const fn set_model_unknown(&mut self, value: bool) {
        self.model_unknown = value;
    }

    /// `FuncProto::printModelInDecl`.
    pub const fn print_model_in_decl(&self) -> bool {
        self.print_model_in_decl
    }

    /// Set whether the model name should be printed in declarations.
    pub const fn set_print_model_in_decl(&mut self, value: bool) {
        self.print_model_in_decl = value;
    }

    /// `FuncProto::isInputLocked`.
    pub fn is_input_locked(&self) -> bool {
        self.input_locked
            || self
                .params
                .first()
                .is_some_and(ProtoParameter::is_type_locked)
    }

    /// `FuncProto::isOutputLocked`.
    pub const fn is_output_locked(&self) -> bool {
        self.output.is_type_locked()
    }

    /// `FuncProto::isModelLocked`.
    pub const fn is_model_locked(&self) -> bool {
        self.model_locked
    }

    /// `FuncProto::hasCustomStorage`.
    pub const fn has_custom_storage(&self) -> bool {
        self.custom_storage
    }

    /// Mark parameter storage as custom rather than model-derived.
    pub const fn set_custom_storage(&mut self, value: bool) {
        self.custom_storage = value;
    }

    /// `FuncProto::setInputLock`.
    pub fn set_input_lock(&mut self, value: bool) {
        self.input_locked = value;
        if value {
            self.model_locked = true;
        }
        for parameter in &mut self.params {
            parameter.set_type_lock(value);
        }
    }

    /// `FuncProto::setOutputLock`.
    pub fn set_output_lock(&mut self, value: bool) {
        if value {
            self.model_locked = true;
        }
        self.output.set_type_lock(value);
    }

    /// `FuncProto::setModelLock`.
    pub const fn set_model_lock(&mut self, value: bool) {
        self.model_locked = value;
    }

    /// `FuncProto::isInline`.
    pub const fn is_inline(&self) -> bool {
        self.inline
    }

    /// `FuncProto::setInline`.
    pub const fn set_inline(&mut self, value: bool) {
        self.inline = value;
    }

    /// `FuncProto::getInjectId`.
    pub const fn get_inject_id(&self) -> i32 {
        self.inject_id
    }

    /// `FuncProto::setInjectId`.
    pub fn set_inject_id(&mut self, value: i32) {
        if value < 0 {
            self.cancel_inject_id();
        } else {
            self.inject_id = value;
            self.inline = true;
        }
    }

    /// `FuncProto::cancelInjectId`.
    pub const fn cancel_inject_id(&mut self) {
        self.inject_id = -1;
        self.inline = false;
    }

    /// `FuncProto::getInjectUponEntry`.
    pub const fn get_inject_upon_entry(&self) -> i32 {
        self.inject_upon_entry
    }

    /// Configure the model's entry injection id.
    pub const fn set_inject_upon_entry(&mut self, value: i32) {
        self.inject_upon_entry = value;
    }

    /// `FuncProto::getInjectUponReturn`.
    pub const fn get_inject_upon_return(&self) -> i32 {
        self.inject_upon_return
    }

    /// Configure the model's return injection id.
    pub const fn set_inject_upon_return(&mut self, value: i32) {
        self.inject_upon_return = value;
    }

    /// `FuncProto::isDotdotdot`.
    pub const fn is_dotdotdot(&self) -> bool {
        self.dotdotdot
    }

    /// Set whether the fixed parameter list is followed by varargs.
    pub const fn set_dotdotdot(&mut self, value: bool) {
        self.dotdotdot = value;
    }

    /// Establish an internal prototype store for an indirect call.
    ///
    /// Ghidra's `setInternal` uses a model for calling-convention decisions
    /// while keeping parameter/output descriptions in an owned internal
    /// store.  The graph representation has no separate store object, so the
    /// equivalent is to clear the old descriptions, retain the model, and
    /// install the supplied default output type as an unlocated value.
    pub fn set_internal(&mut self, abi: Abi, return_type: Type) {
        if !self.has_matching_model(&abi) {
            self.set_model(abi);
        }
        self.params.clear();
        self.input_locked = false;
        self.output = ProtoParameter::new(
            "",
            Location {
                space: 0,
                offset: 0,
                size: 0,
            },
            return_type,
        );
        self.output.set_type_lock(false);
        self.custom_storage = true;
    }

    /// `FuncProto::isNoReturn`.
    pub const fn is_no_return(&self) -> bool {
        self.no_return
    }

    /// `FuncProto::setNoReturn`.
    pub const fn set_no_return(&mut self, value: bool) {
        self.no_return = value;
    }

    /// `FuncProto::hasThisPointer`.
    pub const fn has_this_pointer(&self) -> bool {
        self.has_this_pointer
    }

    /// Set whether this is a method prototype with an implicit `this` input.
    pub fn set_has_this_pointer(&mut self, value: bool) {
        self.has_this_pointer = value;
        if value {
            self.update_this_pointer();
        } else {
            for parameter in &mut self.params {
                parameter.set_this_pointer(false);
            }
        }
    }

    /// `FuncProto::isConstructor`.
    pub const fn is_constructor(&self) -> bool {
        self.constructor
    }

    /// `FuncProto::setConstructor`.
    pub const fn set_constructor(&mut self, value: bool) {
        self.constructor = value;
    }

    /// `FuncProto::isDestructor`.
    pub const fn is_destructor(&self) -> bool {
        self.destructor
    }

    /// `FuncProto::setDestructor`.
    pub const fn set_destructor(&mut self, value: bool) {
        self.destructor = value;
    }

    /// `FuncProto::isOverride`.
    pub const fn is_override(&self) -> bool {
        self.override_callsite
    }

    /// `FuncProto::setOverride`.
    pub const fn set_override(&mut self, value: bool) {
        self.override_callsite = value;
    }

    /// `FuncProto::hasInputErrors`.
    pub const fn has_input_errors(&self) -> bool {
        self.input_errors
    }

    /// `FuncProto::setInputErrors`.
    pub const fn set_input_errors(&mut self, value: bool) {
        self.input_errors = value;
    }

    /// `FuncProto::hasOutputErrors`.
    pub const fn has_output_errors(&self) -> bool {
        self.output_errors
    }

    /// `FuncProto::setOutputErrors`.
    pub const fn set_output_errors(&mut self, value: bool) {
        self.output_errors = value;
    }

    /// `FuncProto::getExtraPop`.
    pub const fn get_extra_pop(&self) -> i32 {
        self.extra_pop
    }

    /// `FuncProto::setExtraPop`.
    pub const fn set_extra_pop(&mut self, value: i32) {
        self.extra_pop = value;
    }

    /// `FuncProto::getReturnBytesConsumed`.
    pub const fn get_return_bytes_consumed(&self) -> u32 {
        self.return_bytes_consumed
    }

    /// `FuncProto::setReturnBytesConsumed`.
    ///
    /// As in Ghidra, zero means "all bytes" and does not replace a useful
    /// nonzero minimum; the smallest nonzero hint wins.
    pub fn set_return_bytes_consumed(&mut self, value: u32) -> bool {
        if value == 0 {
            return false;
        }
        if self.return_bytes_consumed == 0 || value < self.return_bytes_consumed {
            self.return_bytes_consumed = value;
            true
        } else {
            false
        }
    }

    /// `FuncProto::numParams`.
    pub const fn num_params(&self) -> usize {
        self.params.len()
    }

    /// Borrow all input parameters in declaration order.
    pub fn params(&self) -> &[ProtoParameter] {
        &self.params
    }

    /// Borrow all input parameters mutably for graph adapters.
    pub fn params_mut(&mut self) -> &mut [ProtoParameter] {
        &mut self.params
    }

    /// `FuncProto::getParam`.
    pub fn get_param(&self, index: usize) -> Option<&ProtoParameter> {
        self.params.get(index)
    }

    /// Mutable `FuncProto::getParam` for recovery updates.
    pub fn get_param_mut(&mut self, index: usize) -> Option<&mut ProtoParameter> {
        self.params.get_mut(index)
    }

    /// Replace an input parameter at `index`, or append when `index` is the
    /// next free slot.  Gaps are rejected rather than silently inventing
    /// parameters.
    pub fn set_param(&mut self, index: usize, parameter: ProtoParameter) -> bool {
        match index.cmp(&self.params.len()) {
            std::cmp::Ordering::Less => self.params[index] = parameter,
            std::cmp::Ordering::Equal => self.params.push(parameter),
            std::cmp::Ordering::Greater => return false,
        }
        true
    }

    /// Set a parameter from its source-level pieces.
    pub fn set_param_parts<N: Into<String>>(
        &mut self,
        index: usize,
        name: N,
        location: Location,
        ty: Type,
    ) -> bool {
        self.set_param(index, ProtoParameter::new(name, location, ty))
    }

    /// Append an input parameter.
    pub fn add_param(&mut self, parameter: ProtoParameter) {
        self.params.push(parameter);
    }

    /// Append an input parameter from complete pieces.
    pub fn add_param_parts<N: Into<String>>(&mut self, name: N, location: Location, ty: Type) {
        self.add_param(ProtoParameter::new(name, location, ty));
    }

    /// `FuncProto::removeParam`.
    pub fn remove_param(&mut self, index: usize) -> Option<ProtoParameter> {
        (index < self.params.len()).then(|| self.params.remove(index))
    }

    /// `FuncProto::getOutput`.
    pub const fn get_output(&self) -> &ProtoParameter {
        &self.output
    }

    /// Mutable output parameter for recovery updates.
    pub const fn get_output_mut(&mut self) -> &mut ProtoParameter {
        &mut self.output
    }

    /// `FuncProto::setOutput`.
    pub fn set_output(&mut self, parameter: ProtoParameter) {
        self.output = parameter;
    }

    /// Set output storage and type directly.
    pub fn set_output_parts(&mut self, location: Location, ty: Type) {
        self.output = ProtoParameter::new("", location, ty);
    }

    /// `FuncProto::getOutputType`.
    pub fn get_output_type(&self) -> &Type {
        self.output.get_type()
    }

    /// `FuncProto::clearOutput`.
    pub fn clear_output(&mut self) {
        self.output = ProtoParameter::void();
        self.return_bytes_consumed = 0;
    }

    /// Remove all input parameters, including an input lock on a void list.
    pub fn clear_input(&mut self) {
        self.params.clear();
        self.input_locked = false;
    }

    /// `FuncProto::clearUnlockedInput`.
    pub fn clear_unlocked_input(&mut self) -> bool {
        if self.is_input_locked() {
            return false;
        }
        let changed = !self.params.is_empty();
        self.params.clear();
        changed
    }

    /// `FuncProto::clearUnlockedOutput`.
    pub fn clear_unlocked_output(&mut self) -> bool {
        let changed = if self.output.is_type_locked() {
            if self.output.is_size_type_locked() {
                self.output.reset_size_lock_type()
            } else {
                false
            }
        } else {
            let changed = !matches!(self.output.ty, Type::Void) || self.output.location.size != 0;
            self.output = ProtoParameter::void();
            changed
        };
        self.return_bytes_consumed = 0;
        changed
    }

    /// Copy every prototype property and parameter, matching
    /// `FuncProto::copy` without pointer ownership.
    pub fn copy_from(&mut self, other: &Self) {
        *self = other.clone();
    }

    /// Copy only flow properties, matching `FuncProto::copyFlowEffects`.
    pub fn copy_flow_effects(&mut self, other: &Self) {
        self.inline = other.inline;
        self.no_return = other.no_return;
        self.inject_id = other.inject_id;
    }

    /// Establish the model's concrete input/output storage locations.
    pub fn set_model_storage(&mut self, input: Vec<Location>, output: Vec<Location>) {
        self.model_input_locations = input;
        self.model_output_locations = output;
    }

    /// Model input storage entries in calling-convention order.
    pub fn model_input_storage(&self) -> &[Location] {
        &self.model_input_locations
    }

    /// Model output storage entries in calling-convention order.
    pub fn model_output_storage(&self) -> &[Location] {
        &self.model_output_locations
    }

    /// Add the internal compiler-constant storage read by
    /// `ActionInternalStorage`.
    pub fn set_internal_storage(&mut self, storage: Vec<Location>) {
        self.internal_storage = storage;
    }

    /// `FuncProto::internalBegin`/`internalEnd` as one slice.
    pub fn internal_storage(&self) -> &[Location] {
        &self.internal_storage
    }

    /// Configure the address-space byte order used by containment checks.
    pub const fn set_big_endian(&mut self, value: bool) {
        self.big_endian = value;
    }

    /// Whether model storage uses big-endian least-significant-byte placement.
    pub const fn is_big_endian(&self) -> bool {
        self.big_endian
    }

    /// Build one parameter at a model storage slot from a recovered type.
    pub fn parameter_from_model<N: Into<String>>(
        &self,
        index: usize,
        name: N,
        ty: Type,
    ) -> Option<ProtoParameter> {
        let location = *self.model_input_locations.get(index)?;
        Some(ProtoParameter::new(name, location, ty))
    }

    /// Append one model-assigned input parameter.
    pub fn add_model_param<N: Into<String>>(&mut self, name: N, ty: Type) -> bool {
        let index = self.params.len();
        let Some(parameter) = self.parameter_from_model(index, name, ty) else {
            return false;
        };
        self.params.push(parameter);
        true
    }

    /// `ProtoModel::possibleParam` through `FuncProto::possibleInputParam`.
    pub fn possible_input_param(&self, location: Location) -> bool {
        if !self.dotdotdot {
            let mut tested_locked = false;
            for parameter in &self.params {
                if !parameter.is_type_locked() {
                    continue;
                }
                tested_locked = true;
                if self.justified_offset(parameter.location, location) == Some(0) {
                    return true;
                }
            }
            if tested_locked || (self.input_locked && self.params.is_empty()) {
                return false;
            }
        }
        self.model_input_locations
            .iter()
            .any(|entry| self.justified_offset(*entry, location) == Some(0))
    }

    /// `ProtoModel::possibleParam` through `FuncProto::possibleOutputParam`.
    pub fn possible_output_param(&self, location: Location) -> bool {
        if self.is_output_locked() {
            if matches!(self.output.ty, Type::Void) {
                return false;
            }
            return self.justified_offset(self.output.location, location) == Some(0);
        }
        self.model_output_locations
            .iter()
            .any(|entry| self.justified_offset(*entry, location) == Some(0))
    }

    /// `ProtoModel::characterizeAsInputParam` through the function prototype.
    pub fn characterize_as_input_param(&self, location: Location) -> Containment {
        if !self.dotdotdot {
            let mut tested_locked = false;
            let mut result = Containment::NoContainment;
            for parameter in &self.params {
                if !parameter.is_type_locked() {
                    continue;
                }
                tested_locked = true;
                result = result.combine(self.classify(parameter.location, location));
            }
            if tested_locked || (self.input_locked && self.params.is_empty()) {
                return result;
            }
        }
        self.classify_entries(&self.model_input_locations, location)
    }

    /// `ProtoModel::characterizeAsOutput` through the function prototype.
    pub fn characterize_as_output(&self, location: Location) -> Containment {
        if self.is_output_locked() {
            if matches!(self.output.ty, Type::Void) {
                return Containment::NoContainment;
            }
            return self.classify(self.output.location, location);
        }
        self.classify_entries(&self.model_output_locations, location)
    }

    /// `ProtoModel::unjustifiedContainer` through the function prototype.
    pub fn unjustified_input_param(&self, location: Location) -> Option<Location> {
        if !self.dotdotdot {
            let mut tested_locked = false;
            for parameter in &self.params {
                if !parameter.is_type_locked() {
                    continue;
                }
                tested_locked = true;
                let Some(offset) = self.justified_offset(parameter.location, location) else {
                    continue;
                };
                if offset > 0 {
                    return Some(parameter.location);
                }
                return None;
            }
            if tested_locked || (self.input_locked && self.params.is_empty()) {
                return None;
            }
        }
        self.model_input_locations.iter().find_map(|entry| {
            let offset = self.justified_offset(*entry, location)?;
            (offset > 0).then_some(*entry)
        })
    }

    /// `ProtoModel::assumedExtension` through the function prototype.
    ///
    /// The first tuple item is a p-code opcode (`COPY`, `INT_ZEXT`, or
    /// `INT_SEXT`); the second is the containing storage range when an
    /// extension is needed.  ABI entries do not carry extension policy, so
    /// unlocked model entries conservatively return `COPY`.
    pub fn assumed_input_extension(&self, location: Location) -> (i32, Option<Location>) {
        for parameter in &self.params {
            if !parameter.is_type_locked() {
                continue;
            }
            if self.justified_offset(parameter.location, location) != Some(0)
                || parameter.location.size <= location.size
            {
                continue;
            }
            let opcode = extension_opcode(&parameter.ty);
            return (opcode, Some(parameter.location));
        }
        (op::COPY, None)
    }

    /// Output analogue of `ProtoModel::assumedExtension`.
    pub fn assumed_output_extension(&self, location: Location) -> (i32, Option<Location>) {
        if self.is_output_locked()
            && self.output.location.size > location.size
            && self.justified_offset(self.output.location, location) == Some(0)
        {
            return (
                extension_opcode(&self.output.ty),
                Some(self.output.location),
            );
        }
        (op::COPY, None)
    }

    /// Return the largest model/locked input entry wholly contained by a
    /// range, matching `getBiggestContainedInputParam`.
    pub fn biggest_contained_input_param(&self, range: Location) -> Option<Location> {
        let entries = self.locked_input_entries();
        if !entries.is_empty() {
            return entries
                .into_iter()
                .filter(|entry| range_contains(range, *entry))
                .max_by_key(|entry| entry.size);
        }
        self.model_input_locations
            .iter()
            .copied()
            .filter(|entry| range_contains(range, *entry))
            .max_by_key(|entry| entry.size)
    }

    /// Return the largest model/locked output entry wholly contained by a
    /// range, matching `getBiggestContainedOutput`.
    pub fn biggest_contained_output(&self, range: Location) -> Option<Location> {
        if self.is_output_locked() {
            if matches!(self.output.ty, Type::Void) {
                return None;
            }
            return range_contains(range, self.output.location).then_some(self.output.location);
        }
        self.model_output_locations
            .iter()
            .copied()
            .filter(|entry| range_contains(range, *entry))
            .max_by_key(|entry| entry.size)
    }

    /// Return the storage selected for the method's `this` pointer.
    pub fn this_pointer_storage(&self) -> Option<Location> {
        if !self.has_this_pointer {
            return None;
        }
        self.params
            .iter()
            .find(|parameter| !parameter.is_hidden_return())
            .map(ProtoParameter::get_address)
            .or_else(|| self.model_input_locations.first().copied())
    }

    /// Mark the first non-hidden input as the `this` parameter.
    pub fn update_this_pointer(&mut self) {
        if !self.has_this_pointer {
            return;
        }
        let Some(parameter) = self
            .params
            .iter_mut()
            .find(|parameter| !parameter.is_hidden_return())
        else {
            return;
        };
        parameter.set_this_pointer(true);
    }

    /// Resolve the active trials against the one concrete ABI model.
    ///
    /// There is no merged `ProtoModel` in the target ABI layer.  When explicit
    /// model storage is available, active trials outside it are marked `NoUse`;
    /// with no address map, leaving trials untouched is safer than claiming an
    /// arbitrary register.  The return value reports whether any trial changed.
    pub fn derive_input_map(&self, active: &mut ParamActive) -> bool {
        if self.model_input_locations.is_empty() {
            return false;
        }
        let mut changed = false;
        for trial in active.trials_mut() {
            if matches!(trial.state, TrialState::Active)
                && !self.possible_input_param(trial.location)
            {
                trial.mark_no_use();
                changed = true;
            }
        }
        changed
    }

    /// Resolve output trials against the configured output storage model.
    pub fn derive_output_map(&self, active: &mut ParamActive) -> bool {
        if self.model_output_locations.is_empty() {
            return false;
        }
        let mut changed = false;
        for trial in active.trials_mut() {
            if matches!(trial.state, TrialState::Active)
                && !self.possible_output_param(trial.location)
            {
                trial.mark_no_use();
                changed = true;
            }
        }
        changed
    }

    /// Update unlocked inputs from recovered graph types.
    pub fn update_input_types(
        &mut self,
        data: &Funcdata,
        triallist: &[super::VarnodeId],
        active: &ParamActive,
    ) -> usize {
        if self.is_input_locked() {
            return 0;
        }
        let recovered = data.recovered_types();
        let mut updated = Vec::new();
        for trial in active.trials() {
            if !matches!(trial.state, TrialState::Active) {
                continue;
            }
            let Some(index) = trial.slot.checked_sub(1) else {
                continue;
            };
            let Some(value) = triallist.get(index).copied() else {
                continue;
            };
            let ty = recovered
                .1
                .get(value)
                .map(super::typefactory::to_native)
                .unwrap_or_else(|| unknown_type(trial.location.size));
            updated.push(ProtoParameter::new("", trial.location, ty));
        }
        let changed = usize::from(self.params != updated);
        self.params = updated;
        self.update_this_pointer();
        changed
    }

    /// Update unlocked inputs while retaining only storage widths.
    pub fn update_input_no_types(
        &mut self,
        triallist: &[super::VarnodeId],
        active: &ParamActive,
    ) -> usize {
        if self.is_input_locked() {
            return 0;
        }
        let updated: Vec<_> = active
            .trials()
            .iter()
            .filter(|trial| matches!(trial.state, TrialState::Active))
            .filter_map(|trial| {
                let index = trial.slot.checked_sub(1)?;
                triallist.get(index)?;
                Some(ProtoParameter::new(
                    "",
                    trial.location,
                    unknown_type(trial.location.size),
                ))
            })
            .collect();
        let changed = usize::from(self.params != updated);
        self.params = updated;
        changed
    }

    /// Update an unlocked output from a recovered graph value.
    pub fn update_output_types(&mut self, data: &Funcdata, triallist: &[super::VarnodeId]) -> bool {
        if self.is_output_locked() {
            if !self.output.is_size_type_locked() {
                return false;
            }
            let Some(value) = triallist.first().copied() else {
                return false;
            };
            let graph_location = data.varnode(value);
            let location = Location {
                space: graph_location.space,
                offset: graph_location.offset,
                size: graph_location.size,
            };
            if location != self.output.location {
                return false;
            }
            let recovered = data.recovered_types();
            let Some(ty) = recovered.1.get(value).map(super::typefactory::to_native) else {
                return false;
            };
            return self.output.override_size_lock_type(ty);
        }
        let Some(value) = triallist.first().copied() else {
            self.clear_output();
            return true;
        };
        let graph_location = data.varnode(value);
        let location = Location {
            space: graph_location.space,
            offset: graph_location.offset,
            size: graph_location.size,
        };
        let ty = data
            .recovered_types()
            .1
            .get(value)
            .map(super::typefactory::to_native)
            .unwrap_or_else(|| unknown_type(location.size));
        let replacement = ProtoParameter::new("", location, ty);
        let changed = self.output != replacement;
        self.output = replacement;
        changed
    }

    /// Update an unlocked output from storage width only.
    pub fn update_output_no_types(
        &mut self,
        data: &Funcdata,
        triallist: &[super::VarnodeId],
    ) -> bool {
        if self.is_output_locked() {
            return false;
        }
        let Some(value) = triallist.first().copied() else {
            let changed = !matches!(self.output.ty, Type::Void) || self.output.location.size != 0;
            self.clear_output();
            return changed;
        };
        let graph_location = data.varnode(value);
        let location = Location {
            space: graph_location.space,
            offset: graph_location.offset,
            size: graph_location.size,
        };
        let replacement = ProtoParameter::new("", location, Type::Unknown);
        let changed = self.output != replacement;
        self.output = replacement;
        changed
    }

    /// Send the warnings owned by this prototype to the graph warning sink.
    ///
    /// Ghidra's `ActionPrototypeWarnings` emits these messages with
    /// `warningHeader`; Ventris has one deduplicating `Funcdata::warning`
    /// channel, so the semantic message is preserved without a second sink.
    pub fn emit_warnings(&self, data: &mut Funcdata) -> usize {
        let mut emitted = 0;
        if self.input_errors
            && data.warning(
                "Cannot assign parameter locations for this function: Prototype may be inaccurate",
            )
        {
            emitted += 1;
        }
        if self.output_errors && data.warning(
            "Cannot assign location of return value for this function: Return value may be inaccurate",
        ) {
            emitted += 1;
        }
        if self.model_unknown {
            let mut message = String::from("Unknown calling convention");
            if self.print_model_in_decl {
                message.push_str(": ");
                message.push_str(self.abi.name);
            }
            if !self.custom_storage && (self.is_input_locked() || self.is_output_locked()) {
                message.push_str(" -- yet parameter storage is locked");
            }
            if data.warning(message) {
                emitted += 1;
            }
        }
        emitted
    }

    fn locked_input_entries(&self) -> Vec<Location> {
        self.params
            .iter()
            .filter(|parameter| parameter.is_type_locked())
            .map(ProtoParameter::get_address)
            .collect()
    }

    fn classify_entries(&self, entries: &[Location], location: Location) -> Containment {
        let mut result = Containment::NoContainment;
        for entry in entries {
            result = result.combine(self.classify(*entry, location));
            if matches!(result, Containment::ContainsJustified) {
                return result;
            }
        }
        result
    }

    fn classify(&self, entry: Location, location: Location) -> Containment {
        if self.justified_offset(entry, location) == Some(0) {
            return Containment::ContainsJustified;
        }
        if self.justified_offset(entry, location).is_some() {
            return Containment::ContainsUnjustified;
        }
        if range_contains(location, entry) {
            return Containment::ContainedBy;
        }
        Containment::NoContainment
    }

    fn justified_offset(&self, entry: Location, location: Location) -> Option<u32> {
        if entry.space != location.space || location.size == 0 || entry.size == 0 {
            return None;
        }
        let entry_end = entry.offset.checked_add(u64::from(entry.size))?;
        let location_end = location.offset.checked_add(u64::from(location.size))?;
        if location.offset < entry.offset || location_end > entry_end {
            return None;
        }
        let offset = if self.big_endian {
            entry_end.checked_sub(location_end)?
        } else {
            location.offset.checked_sub(entry.offset)?
        };
        u32::try_from(offset).ok()
    }
}

impl Containment {
    fn combine(self, other: Self) -> Self {
        match (self, other) {
            (Self::ContainsJustified, _) | (_, Self::ContainsJustified) => Self::ContainsJustified,
            (Self::ContainsUnjustified, _) | (_, Self::ContainsUnjustified) => {
                Self::ContainsUnjustified
            }
            (Self::ContainedBy, _) | (_, Self::ContainedBy) => Self::ContainedBy,
            _ => Self::NoContainment,
        }
    }
}

fn range_contains(container: Location, contained: Location) -> bool {
    if container.space != contained.space || container.size == 0 || contained.size == 0 {
        return false;
    }
    let Some(container_end) = container.offset.checked_add(u64::from(container.size)) else {
        return false;
    };
    let Some(contained_end) = contained.offset.checked_add(u64::from(contained.size)) else {
        return false;
    };
    contained.offset >= container.offset && contained_end <= container_end
}

fn type_size(ty: &Type, fallback: u32) -> u32 {
    match ty {
        Type::Unknown | Type::Void => fallback,
        Type::Bool => 1,
        Type::Unsigned(bits) | Type::Signed(bits) | Type::Float(bits) => bits.div_ceil(8),
        Type::Pointer(_) => fallback,
    }
}

fn unknown_type(_size: u32) -> Type {
    Type::Unknown
}

fn extension_opcode(ty: &Type) -> i32 {
    match ty {
        Type::Signed(_) => op::INT_SEXT,
        Type::Unsigned(_) | Type::Bool | Type::Pointer(_) => op::INT_ZEXT,
        Type::Unknown | Type::Float(_) | Type::Void => op::COPY,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ventris_lifter::REGISTER_SPACE;
    use ventris_target::TargetProfile;

    fn location(offset: u64, size: u32) -> Location {
        Location {
            space: REGISTER_SPACE,
            offset,
            size,
        }
    }

    fn prototype() -> FuncProto {
        FuncProto::with_storage(
            TargetProfile::Ps2.spec().abi,
            vec![location(0x20, 4), location(0x24, 8)],
            vec![location(0x40, 4)],
        )
    }

    #[test]
    fn parameter_carries_storage_type_name_and_lock_decisions() {
        let mut parameter = ProtoParameter::new("count", location(0x20, 4), Type::Unknown);
        assert_eq!(parameter.get_name(), "count");
        assert_eq!(parameter.get_address(), location(0x20, 4));
        assert_eq!(parameter.get_size(), 4);
        assert_eq!(parameter.get_type(), &Type::Unknown);
        assert!(!parameter.is_type_locked());
        assert!(!parameter.is_size_type_locked());

        parameter.set_type_lock(true);
        assert!(parameter.is_type_locked());
        assert!(parameter.is_size_type_locked());
        assert!(parameter.override_size_lock_type(Type::Unsigned(32)));
        assert_eq!(parameter.get_type(), &Type::Unsigned(32));
        assert!(parameter.is_size_type_locked());
        assert!(!parameter.override_size_lock_type(Type::Unsigned(64)));

        parameter.set_type_lock(false);
        assert!(!parameter.is_type_locked());
        assert!(!parameter.is_size_type_locked());
        assert!(parameter.is_name_undefined() == false);
    }

    #[test]
    fn function_lock_unlock_and_model_storage_are_observable() {
        let mut proto = prototype();
        assert_eq!(proto.num_params(), 0);
        assert!(proto.add_model_param("first", Type::Unsigned(32)));
        assert!(proto.add_model_param("wide", Type::Signed(64)));
        assert_eq!(proto.get_param(0).unwrap().get_address(), location(0x20, 4));
        assert_eq!(proto.get_param(1).unwrap().get_type(), &Type::Signed(64));

        proto.set_input_lock(true);
        assert!(proto.is_input_locked());
        assert!(proto.is_model_locked());
        assert!(proto.get_param(0).unwrap().is_type_locked());
        assert!(proto.get_param(1).unwrap().is_type_locked());
        assert!(proto.possible_input_param(location(0x20, 4)));
        assert!(!proto.possible_input_param(location(0x28, 4)));

        proto.set_input_lock(false);
        assert!(!proto.is_input_locked());
        assert!(!proto.get_param(0).unwrap().is_type_locked());
        assert!(proto.clear_unlocked_input());
        assert_eq!(proto.num_params(), 0);

        proto.set_output_parts(location(0x40, 4), Type::Unsigned(32));
        proto.set_output_lock(true);
        assert!(proto.is_output_locked());
        assert!(proto.possible_output_param(location(0x40, 4)));
        proto.set_output_lock(false);
        assert!(!proto.is_output_locked());
        assert!(proto.clear_unlocked_output());
        assert_eq!(proto.get_output_type(), &Type::Void);
    }

    #[test]
    fn containment_and_unjustified_storage_follow_byte_order() {
        let mut proto = prototype();
        proto.set_input_lock(true);
        proto.set_param_parts(0, "word", location(0x20, 8), Type::Unsigned(64));
        proto.get_param_mut(0).unwrap().set_type_lock(true);

        assert_eq!(
            proto.characterize_as_input_param(location(0x20, 4)),
            Containment::ContainsJustified
        );
        assert_eq!(
            proto.unjustified_input_param(location(0x24, 4)),
            Some(location(0x20, 8))
        );
        assert!(!proto.possible_input_param(location(0x24, 4)));

        proto.set_big_endian(true);
        assert_eq!(
            proto.characterize_as_input_param(location(0x24, 4)),
            Containment::ContainsJustified
        );
        assert_eq!(
            proto.characterize_as_input_param(location(0x20, 4)),
            Containment::ContainsUnjustified
        );
    }

    #[test]
    fn output_type_recovery_and_return_consumption_keep_smallest_hint() {
        let mut proto = prototype();
        proto.set_return_bytes_consumed(8);
        assert_eq!(proto.get_return_bytes_consumed(), 8);
        assert!(!proto.set_return_bytes_consumed(16));
        assert!(proto.set_return_bytes_consumed(4));
        assert_eq!(proto.get_return_bytes_consumed(), 4);

        proto.set_output_parts(location(0x40, 4), Type::Unknown);
        proto.set_output_lock(true);
        assert!(proto.get_output().is_size_type_locked());
        assert!(
            proto
                .get_output_mut()
                .override_size_lock_type(Type::Unsigned(32))
        );
        assert_eq!(proto.get_output_type(), &Type::Unsigned(32));
        proto.set_output_lock(false);
        assert!(!proto.is_output_locked());
    }

    #[test]
    fn flags_and_warning_sink_are_deduplicated() {
        let mut proto = prototype();
        proto.set_model_unknown(true);
        proto.set_input_errors(true);
        proto.set_no_return(true);
        proto.set_inline(true);
        proto.set_has_this_pointer(true);
        assert!(proto.is_no_return());
        assert!(proto.is_inline());
        assert!(proto.has_this_pointer());

        let mut data = Funcdata::default();
        assert_eq!(proto.emit_warnings(&mut data), 2);
        assert_eq!(proto.emit_warnings(&mut data), 0);
        assert_eq!(data.warnings().len(), 2);
    }
}
