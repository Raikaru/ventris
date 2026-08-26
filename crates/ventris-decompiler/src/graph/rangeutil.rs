//! Modular integer range algebra from Ghidra's `CircleRange`.
//!
//! The implementation follows `CircleRange` in
//! `Ghidra/Features/Decompiler/src/decompile/cpp/rangeutil.cc` and
//! `rangeutil.hh` at commit `8b4c91d4d5bd1549622bfbade0df199585b98365`.

use ventris_pcode::op;

use super::{Funcdata, OpId, VarnodeId};

const OVERLAP_ARRANGE: &[u8; 64] =
    b"gcgbegdagggggggeggggcgbggggggggcdfgggggggegdggggbgggfggggcgbegda";

fn calc_mask(size: u32) -> u64 {
    let bits = size.saturating_mul(8);
    if bits == 0 {
        0
    } else if bits >= 64 {
        u64::MAX
    } else {
        (1u64 << bits) - 1
    }
}

fn shift_left(value: u64, amount: u64) -> u64 {
    if amount >= 64 {
        0
    } else {
        value.wrapping_shl(amount as u32)
    }
}

fn shift_right(value: u64, amount: u64) -> u64 {
    if amount >= 64 { 0 } else { value >> amount }
}

fn sign_extend(value: u64, input_size: u32, output_size: u32) -> u64 {
    let input_mask = calc_mask(input_size);
    let output_mask = calc_mask(output_size);
    let bits = input_size.saturating_mul(8);
    if bits == 0 || bits > 64 {
        return value & output_mask;
    }
    let value = value & input_mask;
    let sign = 1u64 << (bits - 1);
    let extended = if value & sign != 0 {
        value | !input_mask
    } else {
        value
    };
    extended & output_mask
}

fn bit_transitions(mut value: u64, size: u32) -> u32 {
    let bits = size.saturating_mul(8).min(64);
    if bits == 0 {
        return 0;
    }
    let mut transitions = 0;
    let mut previous = value & 1;
    for _ in 1..bits {
        value >>= 1;
        let current = value & 1;
        if current != previous {
            transitions += 1;
            previous = current;
        }
        if value == 0 {
            break;
        }
    }
    transitions
}

fn most_significant_bit(value: u64) -> Option<u32> {
    (value != 0).then_some(63 - value.leading_zeros())
}

/// A modular half-open integer range, ported from Ghidra's `CircleRange`.
///
/// Ghidra represents values in the circular domain `0..=mask`; `left` is the
/// first value, `right` is the exclusive endpoint, and `step` is the stride.
/// A non-empty range with equal endpoints is the complete domain for stride
/// one, or one residue class for a larger stride.  See
/// `CircleRange` in `rangeutil.hh:29-58` and `rangeutil.cc:23-35`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CircleRange {
    left: u64,
    right: u64,
    mask: u64,
    step: u32,
    isempty: bool,
}

impl Default for CircleRange {
    fn default() -> Self {
        Self::new()
    }
}

impl CircleRange {
    /// Construct an empty range.
    ///
    /// This is `CircleRange::CircleRange(void)` from `rangeutil.hh:64`.
    pub const fn new() -> Self {
        Self {
            left: 0,
            right: 0,
            mask: 0,
            step: 1,
            isempty: true,
        }
    }

    /// Construct a range from circular boundaries and a byte-sized domain.
    ///
    /// This is `CircleRange::CircleRange(uintb,uintb,int4,int4)` from
    /// `rangeutil.cc:179-187` and `rangeutil.hh:65`.
    pub fn from_bounds(left: u64, right: u64, size: u32, step: u32) -> Self {
        let mask = calc_mask(size);
        let range = Self {
            left: left & mask,
            right: right & mask,
            mask,
            step: step.max(1),
            isempty: false,
        };
        range
    }

    /// Construct the singleton boolean range for `value`.
    ///
    /// This is `CircleRange::CircleRange(bool)` from `rangeutil.cc:191-199`
    /// and `rangeutil.hh:66`.
    pub fn from_bool(value: bool) -> Self {
        Self {
            left: u64::from(value),
            right: u64::from(value) + 1,
            mask: 0xff,
            step: 1,
            isempty: false,
        }
    }

    /// Construct the singleton range containing `value` in a byte-sized domain.
    ///
    /// This is `CircleRange::CircleRange(uintb,int4)` from
    /// `rangeutil.cc:205-213` and `rangeutil.hh:67`.
    pub fn from_value(value: u64, size: u32) -> Self {
        let mask = calc_mask(size);
        Self {
            left: value & mask,
            right: (value.wrapping_add(1)) & mask,
            mask,
            step: 1,
            isempty: false,
        }
    }

    /// Re-establish Ghidra's canonical representation of a full residue class.
    ///
    /// This is `CircleRange::normalize` from `rangeutil.cc:25-35` and
    /// `rangeutil.hh:57`.
    pub fn normalize(&mut self) {
        if self.left == self.right {
            if self.step != 1 {
                self.left %= u64::from(self.step);
            } else {
                self.left = 0;
            }
            self.right = self.left;
        }
    }

    /// Set explicit boundaries, domain size, and stride.
    ///
    /// This is `CircleRange::setRange(uintb,uintb,int4,int4)` from
    /// `rangeutil.cc:219-227` and `rangeutil.hh:68`.
    pub fn set_range(&mut self, left: u64, right: u64, size: u32, step: u32) {
        self.mask = calc_mask(size);
        self.left = left & self.mask;
        self.right = right & self.mask;
        self.step = step.max(1);
        self.isempty = false;
    }

    /// Set this range to one value in a byte-sized domain.
    ///
    /// This is `CircleRange::setRange(uintb,int4)` from
    /// `rangeutil.cc:233-241` and `rangeutil.hh:69`.
    pub fn set_value(&mut self, value: u64, size: u32) {
        self.mask = calc_mask(size);
        self.step = 1;
        self.left = value & self.mask;
        self.right = value.wrapping_add(1) & self.mask;
        self.isempty = false;
    }

    /// Set this range to all values in a byte-sized domain.
    ///
    /// This is `CircleRange::setFull` from `rangeutil.cc:245-253` and
    /// `rangeutil.hh:70`.
    pub fn set_full(&mut self, size: u32) {
        self.mask = calc_mask(size);
        self.step = 1;
        self.left = 0;
        self.right = 0;
        self.isempty = false;
    }

    /// Return whether this range contains no values.
    ///
    /// This is `CircleRange::isEmpty` from `rangeutil.hh:71`.
    pub const fn is_empty(&self) -> bool {
        self.isempty
    }

    /// Return whether this range contains every value in its domain.
    ///
    /// This is `CircleRange::isFull` from `rangeutil.hh:72`.
    pub const fn is_full(&self) -> bool {
        !self.isempty && self.step == 1 && self.left == self.right
    }

    /// Return whether this range contains exactly one value.
    ///
    /// This is `CircleRange::isSingle` from `rangeutil.hh:73`.
    pub fn is_single(&self) -> bool {
        !self.isempty && self.right == self.left.wrapping_add(u64::from(self.step)) & self.mask
    }

    /// Return the first value in the range.
    ///
    /// This is `CircleRange::getMin` from `rangeutil.hh:74`.
    pub const fn get_min(&self) -> u64 {
        self.left
    }

    /// Return the last value in the range.
    ///
    /// This is `CircleRange::getMax` from `rangeutil.hh:75`.
    pub fn get_max(&self) -> u64 {
        self.right.wrapping_sub(u64::from(self.step)) & self.mask
    }

    /// Return the exclusive endpoint of the range.
    ///
    /// This is `CircleRange::getEnd` from `rangeutil.hh:76`.
    pub const fn get_end(&self) -> u64 {
        self.right
    }

    /// Return the circular domain mask.
    ///
    /// This is `CircleRange::getMask` from `rangeutil.hh:77`.
    pub const fn get_mask(&self) -> u64 {
        self.mask
    }

    /// Return the number of values represented by the range.
    ///
    /// This is `CircleRange::getSize` from `rangeutil.cc:256-274` and
    /// `rangeutil.hh:78`.
    pub fn get_size(&self) -> u64 {
        if self.isempty {
            return 0;
        }
        let step = u64::from(self.step);
        let mut value = if self.left < self.right {
            (self.right - self.left) / step
        } else {
            (self
                .mask
                .wrapping_sub(self.left - self.right)
                .wrapping_add(step))
                / step
        };
        if value == 0 {
            // Ghidra deliberately lies by one for a complete uintb domain;
            // preserve that behavior for callers such as jump-table analysis.
            value = self.mask;
            if self.step > 1 {
                value = value / step + 1;
            }
        }
        value
    }

    /// Return the stride used by this range.
    ///
    /// This is `CircleRange::getStep` from `rangeutil.hh:79`.
    pub const fn get_step(&self) -> u32 {
        self.step
    }

    /// Advance `value` by one range element and report whether it is not the
    /// exclusive endpoint.
    ///
    /// This is `CircleRange::getNext` from `rangeutil.hh:82`.
    pub fn get_next(&self, value: &mut u64) -> bool {
        *value = value.wrapping_add(u64::from(self.step)) & self.mask;
        *value != self.right
    }

    /// Test whether this range contains one integer.
    ///
    /// This is `CircleRange::contains(uintb)` from `rangeutil.cc:334-352` and
    /// `rangeutil.hh:84`.
    pub fn contains(&self, value: u64) -> bool {
        if self.isempty {
            return false;
        }
        let value = value & self.mask;
        if self.step != 1 && self.left % u64::from(self.step) != value % u64::from(self.step) {
            return false;
        }
        if self.left < self.right {
            value >= self.left && value < self.right
        } else if self.right < self.left {
            value < self.right || value >= self.left
        } else {
            true
        }
    }

    /// Test whether this range contains another range.
    ///
    /// This is `CircleRange::contains(const CircleRange&)` from
    /// `rangeutil.cc:301-329` and `rangeutil.hh:83`.
    pub fn contains_range(&self, other: &Self) -> bool {
        if self.isempty {
            return other.isempty;
        }
        if other.isempty {
            return true;
        }
        if self.step > other.step && !other.is_single() {
            return false;
        }
        if self.left == self.right {
            return true;
        }
        if other.left == other.right {
            return false;
        }
        if self.left % u64::from(self.step) != other.left % u64::from(self.step) {
            return false;
        }
        if self.left == other.left && self.right == other.right {
            return true;
        }
        match Self::encode_range_overlaps(self.left, self.right, other.left, other.right) {
            'c' => true,
            'b' => self.right == other.right,
            _ => false,
        }
    }

    /// Intersect this range with `other` when the result is one range.
    ///
    /// Returns zero when the result is represented by this object, including
    /// an empty result, and two when the intersection would require two pieces.
    /// This is `CircleRange::intersect` from `rangeutil.cc:549-664` and
    /// `rangeutil.hh:85`.
    pub fn intersect(&mut self, other: &Self) -> i32 {
        let mut my_left = self.left;
        let mut my_right = self.right;
        let mut other_left = other.left;
        let mut other_right = other.right;
        let new_step;

        if self.isempty {
            return 0;
        }
        if other.isempty {
            self.isempty = true;
            return 0;
        }
        if self.step < other.step {
            new_step = other.step;
            let remainder = other_left % u64::from(new_step);
            if Self::new_stride(
                self.mask,
                new_step,
                self.step,
                remainder,
                &mut my_left,
                &mut my_right,
            ) {
                self.isempty = true;
                return 0;
            }
        } else if other.step < self.step {
            new_step = self.step;
            let remainder = my_left % u64::from(new_step);
            if Self::new_stride(
                other.mask,
                new_step,
                other.step,
                remainder,
                &mut other_left,
                &mut other_right,
            ) {
                self.isempty = true;
                return 0;
            }
        } else {
            new_step = self.step;
        }

        let new_mask = self.mask & other.mask;
        if self.mask != new_mask {
            if Self::new_domain(new_mask, new_step, &mut my_left, &mut my_right) {
                self.isempty = true;
                return 0;
            }
        } else if other.mask != new_mask
            && Self::new_domain(new_mask, new_step, &mut other_left, &mut other_right)
        {
            self.isempty = true;
            return 0;
        }

        let result = if my_left == my_right {
            self.left = other_left;
            self.right = other_right;
            0
        } else if other_left == other_right {
            self.left = my_left;
            self.right = my_right;
            0
        } else {
            match Self::encode_range_overlaps(my_left, my_right, other_left, other_right) {
                'a' | 'f' => {
                    self.isempty = true;
                    0
                }
                'b' => {
                    self.left = other_left;
                    self.right = my_right;
                    if self.left == self.right {
                        self.isempty = true;
                    }
                    0
                }
                'c' => {
                    self.left = other_left;
                    self.right = other_right;
                    0
                }
                'd' => {
                    self.left = my_left;
                    self.right = my_right;
                    0
                }
                'e' => {
                    self.left = my_left;
                    self.right = other_right;
                    if self.left == self.right {
                        self.isempty = true;
                    }
                    0
                }
                'g' => {
                    if my_left == other_right {
                        self.left = other_left;
                        self.right = my_right;
                        if self.left == self.right {
                            self.isempty = true;
                        }
                        0
                    } else if other_left == my_right {
                        self.left = my_left;
                        self.right = other_right;
                        if self.left == self.right {
                            self.isempty = true;
                        }
                        0
                    } else {
                        2
                    }
                }
                _ => 2,
            }
        };
        if result == 0 {
            self.mask = new_mask;
            self.step = new_step;
        }
        result
    }

    /// Set the range from a nonzero-bit mask when that mask is representable.
    ///
    /// This is `CircleRange::setNZMask` from `rangeutil.cc:672-701` and
    /// `rangeutil.hh:86`; it is used by `pull_back` when the caller requests
    /// nonzero-mask refinement.
    pub fn set_nz_mask(&mut self, nonzero_mask: u64, size: u32) -> bool {
        let transitions = bit_transitions(nonzero_mask, size);
        if transitions > 2 {
            return false;
        }
        let has_step = nonzero_mask & 1 == 0;
        if !has_step && transitions == 2 {
            return false;
        }
        let shift = nonzero_mask.trailing_zeros();
        if transitions != 0 && shift >= 31 {
            return false;
        }
        self.isempty = false;
        if transitions == 0 {
            self.mask = calc_mask(size);
            self.step = 1;
            if has_step {
                self.left = 0;
                self.right = 1;
            } else {
                self.left = 0;
                self.right = 0;
            }
            return true;
        }
        self.step = 1u32 << shift;
        self.mask = calc_mask(size);
        self.left = 0;
        self.right = nonzero_mask.wrapping_add(u64::from(self.step)) & self.mask;
        true
    }

    /// Union two ranges when their exact union is one range.
    ///
    /// Returns zero for a represented union and two when two pieces or
    /// incompatible domains/strides are required.  On return two this range
    /// is unchanged.  This is `CircleRange::circleUnion` from
    /// `rangeutil.cc:360-444` and `rangeutil.hh:87`.
    pub fn circle_union(&mut self, other: &Self) -> i32 {
        if other.isempty {
            return 0;
        }
        if self.isempty {
            *self = *other;
            return 0;
        }
        if self.mask != other.mask {
            return 2;
        }
        let mut other_right = other.right;
        let mut new_step = self.step;
        let mut this_right = self.right;
        if self.step < other.step {
            if self.is_single() {
                new_step = other.step;
                this_right = self.left.wrapping_add(u64::from(new_step)) & self.mask;
            } else {
                return 2;
            }
        } else if other.step < self.step {
            if other.is_single() {
                new_step = self.step;
                other_right = other.left.wrapping_add(u64::from(new_step)) & self.mask;
            } else {
                return 2;
            }
        }
        self.circle_union_with(other, new_step, this_right, other_right)
    }

    fn circle_union_with(
        &mut self,
        other: &Self,
        new_step: u32,
        this_right: u64,
        other_right: u64,
    ) -> i32 {
        let remainder = if new_step != 1 {
            let rem = self.left % u64::from(new_step);
            if rem != other.left % u64::from(new_step) {
                return 2;
            }
            rem
        } else {
            0
        };
        if self.left == this_right || other.left == other_right {
            self.left = remainder;
            self.right = remainder;
            self.step = new_step;
            return 0;
        }
        match Self::encode_range_overlaps(self.left, this_right, other.left, other_right) {
            'a' | 'f' => {
                if this_right == other.left {
                    self.right = other_right;
                    self.step = new_step;
                    0
                } else if self.left == other_right {
                    self.left = other.left;
                    self.right = this_right;
                    self.step = new_step;
                    0
                } else {
                    2
                }
            }
            'b' => {
                self.right = other_right;
                self.step = new_step;
                0
            }
            'c' => {
                self.right = this_right;
                self.step = new_step;
                0
            }
            'd' => {
                self.left = other.left;
                self.right = other_right;
                self.step = new_step;
                0
            }
            'e' => {
                self.left = other.left;
                self.right = this_right;
                self.step = new_step;
                0
            }
            'g' => {
                self.left = remainder;
                self.right = remainder;
                self.step = new_step;
                0
            }
            _ => -1,
        }
    }
    /// Change the stride, retaining the first and last represented values.
    ///
    /// This is `CircleRange::setStride` from `rangeutil.cc:707-722` and
    /// `rangeutil.hh:90`.
    pub fn set_stride(&mut self, new_step: u32, remainder: u64) {
        let new_step = new_step.max(1);
        let was_everything = !self.isempty && self.left == self.right;
        if new_step == self.step {
            return;
        }
        let mut right = self.right.wrapping_sub(u64::from(self.step));
        self.step = new_step;
        if self.step == 1 {
            return;
        }
        let current_remainder = self.left % u64::from(self.step);
        self.left = self
            .left
            .wrapping_sub(current_remainder)
            .wrapping_add(remainder);
        let current_remainder = right % u64::from(self.step);
        right = right
            .wrapping_sub(current_remainder)
            .wrapping_add(remainder);
        self.right = right.wrapping_add(u64::from(self.step));
        if !was_everything && self.left == self.right {
            self.isempty = true;
        }
    }

    /// Pull this output range backward through one unary p-code operation.
    ///
    /// This is `CircleRange::pullBackUnary` from `rangeutil.cc:728-799` and
    /// `rangeutil.hh:91`.
    pub fn pull_back_unary(&mut self, opcode: i32, input_size: u32, output_size: u32) -> bool {
        if self.isempty {
            return true;
        }
        match opcode {
            op::BOOL_NEGATE => {
                if self.convert_to_boolean() {
                    return true;
                }
                self.left ^= 1;
                self.right = self.left + 1;
            }
            op::COPY => {}
            op::INT_2COMP => {
                let value = (!self.left)
                    .wrapping_add(1)
                    .wrapping_add(u64::from(self.step))
                    & self.mask;
                self.left = (!self.right)
                    .wrapping_add(1)
                    .wrapping_add(u64::from(self.step))
                    & self.mask;
                self.right = value;
            }
            op::INT_NEGATE => {
                let value = (!self.left).wrapping_add(u64::from(self.step)) & self.mask;
                self.left = (!self.right).wrapping_add(u64::from(self.step)) & self.mask;
                self.right = value;
            }
            op::INT_ZEXT => {
                let input_mask = calc_mask(input_size);
                let remainder = self.left % u64::from(self.step);
                let zext = Self {
                    left: remainder,
                    right: input_mask.wrapping_add(1).wrapping_add(remainder),
                    mask: self.mask,
                    step: self.step,
                    isempty: false,
                };
                if self.intersect(&zext) != 0 {
                    return false;
                }
                self.left &= input_mask;
                self.right &= input_mask;
                self.mask &= input_mask;
            }
            op::INT_SEXT => {
                let input_mask = calc_mask(input_size);
                // This follows Ghidra's bitwise remainder expression exactly;
                // it is intentional rather than a modulo operation.
                let remainder = self.left & u64::from(self.step);
                let mut sext = Self {
                    left: (input_mask ^ (input_mask >> 1)).wrapping_add(remainder),
                    right: 0,
                    mask: self.mask,
                    step: self.step,
                    isempty: false,
                };
                sext.right = sign_extend(sext.left, input_size, output_size);
                if sext.intersect(self) != 0 {
                    return false;
                }
                if !sext.is_empty() {
                    return false;
                }
                self.left &= input_mask;
                self.right &= input_mask;
                self.mask &= input_mask;
            }
            _ => return false,
        }
        true
    }

    /// Pull this output range backward through a binary p-code operation with
    /// one constant input.
    ///
    /// This is `CircleRange::pullBackBinary` from `rangeutil.cc:807-1003` and
    /// `rangeutil.hh:92`.
    pub fn pull_back_binary(
        &mut self,
        opcode: i32,
        value: u64,
        slot: usize,
        input_size: u32,
        _output_size: u32,
    ) -> bool {
        if self.isempty {
            return true;
        }
        let both_true_false;
        let complement;
        match opcode {
            op::INT_EQUAL => {
                both_true_false = self.convert_to_boolean();
                self.mask = calc_mask(input_size);
                if both_true_false {
                    return true;
                }
                complement = self.left == 0;
                self.left = value;
                self.right = value.wrapping_add(1) & self.mask;
                if complement {
                    self.complement();
                }
            }
            op::INT_NOTEQUAL => {
                both_true_false = self.convert_to_boolean();
                self.mask = calc_mask(input_size);
                if both_true_false {
                    return true;
                }
                complement = self.left == 0;
                self.left = value.wrapping_add(1) & self.mask;
                self.right = value;
                if complement {
                    self.complement();
                }
            }
            op::INT_LESS => {
                both_true_false = self.convert_to_boolean();
                self.mask = calc_mask(input_size);
                if both_true_false {
                    return true;
                }
                complement = self.left == 0;
                if slot == 0 {
                    if value == 0 {
                        self.isempty = true;
                    } else {
                        self.left = 0;
                        self.right = value;
                    }
                } else if value == self.mask {
                    self.isempty = true;
                } else {
                    self.left = value.wrapping_add(1) & self.mask;
                    self.right = 0;
                }
                if complement {
                    self.complement();
                }
            }
            op::INT_LESSEQUAL => {
                both_true_false = self.convert_to_boolean();
                self.mask = calc_mask(input_size);
                if both_true_false {
                    return true;
                }
                complement = self.left == 0;
                if slot == 0 {
                    self.left = 0;
                    self.right = value.wrapping_add(1) & self.mask;
                } else {
                    self.left = value;
                    self.right = 0;
                }
                if complement {
                    self.complement();
                }
            }
            op::INT_SLESS => {
                both_true_false = self.convert_to_boolean();
                self.mask = calc_mask(input_size);
                if both_true_false {
                    return true;
                }
                complement = self.left == 0;
                let negative_infinity = (self.mask >> 1).wrapping_add(1);
                if slot == 0 {
                    if value == negative_infinity {
                        self.isempty = true;
                    } else {
                        self.left = negative_infinity;
                        self.right = value;
                    }
                } else if value == self.mask >> 1 {
                    self.isempty = true;
                } else {
                    self.left = value.wrapping_add(1) & self.mask;
                    self.right = negative_infinity;
                }
                if complement {
                    self.complement();
                }
            }
            op::INT_SLESSEQUAL => {
                both_true_false = self.convert_to_boolean();
                self.mask = calc_mask(input_size);
                if both_true_false {
                    return true;
                }
                complement = self.left == 0;
                let negative_infinity = (self.mask >> 1).wrapping_add(1);
                if slot == 0 {
                    self.left = negative_infinity;
                    self.right = value.wrapping_add(1) & self.mask;
                } else {
                    self.left = value;
                    self.right = negative_infinity;
                }
                if complement {
                    self.complement();
                }
            }
            op::INT_CARRY => {
                both_true_false = self.convert_to_boolean();
                self.mask = calc_mask(input_size);
                if both_true_false {
                    return true;
                }
                complement = self.left == 0;
                if value == 0 {
                    self.isempty = true;
                } else {
                    self.left = self.mask.wrapping_sub(value).wrapping_add(1) & self.mask;
                    self.right = 0;
                }
                if complement {
                    self.complement();
                }
            }
            op::INT_ADD => {
                self.left = self.left.wrapping_sub(value) & self.mask;
                self.right = self.right.wrapping_sub(value) & self.mask;
            }
            op::INT_SUB => {
                if slot == 0 {
                    self.left = self.left.wrapping_add(value) & self.mask;
                    self.right = self.right.wrapping_add(value) & self.mask;
                } else {
                    self.left = value.wrapping_sub(self.left) & self.mask;
                    self.right = value.wrapping_sub(self.right) & self.mask;
                }
            }
            op::INT_RIGHT => {
                if self.step != 1 {
                    return false;
                }
                let right_bound = shift_right(calc_mask(input_size), value).wrapping_add(1);
                if (self.left >= right_bound
                    && self.right >= right_bound
                    && self.left >= self.right)
                    || (self.left == 0 && self.right >= right_bound)
                    || self.left == self.right
                {
                    self.left = 0;
                    self.right = 0;
                } else {
                    if self.left > right_bound {
                        self.left = right_bound;
                    }
                    if self.right > right_bound {
                        self.right = 0;
                    }
                    self.left = shift_left(self.left, value) & self.mask;
                    self.right = shift_left(self.right, value) & self.mask;
                    if self.left == self.right {
                        self.isempty = true;
                    }
                }
            }
            op::INT_SRIGHT => {
                if self.step != 1 {
                    return false;
                }
                let right_bound = calc_mask(input_size);
                let left_bound = shift_right(right_bound, value.wrapping_add(1));
                let right_bound = left_bound ^ right_bound;
                let left_bound = left_bound.wrapping_add(1);
                if (self.left >= left_bound
                    && self.left <= right_bound
                    && self.right >= left_bound
                    && self.right <= right_bound
                    && self.left >= self.right)
                    || self.left == self.right
                {
                    self.left = 0;
                    self.right = 0;
                } else {
                    if self.left > left_bound && self.left < right_bound {
                        self.left = left_bound;
                    }
                    if self.right > left_bound && self.right < right_bound {
                        self.right = right_bound;
                    }
                    self.left = shift_left(self.left, value) & self.mask;
                    self.right = shift_left(self.right, value) & self.mask;
                    if self.left == self.right {
                        self.isempty = true;
                    }
                }
            }
            _ => return false,
        }
        true
    }

    /// Pull this range backward through a graph operation with one unknown
    /// input and at most one constant input.
    ///
    /// The returned varnode is the unknown input.  This is
    /// `CircleRange::pullBack` from `rangeutil.cc:1022-1083` and
    /// `rangeutil.hh:94`; graph operations have no `SymbolEntry`, so the C++
    /// `constMarkup` propagation has no representation here.
    pub fn pull_back(
        &mut self,
        data: &Funcdata,
        operation: OpId,
        use_nz_mask: bool,
    ) -> Option<VarnodeId> {
        let (opcode, inputs, output) = {
            let operation = data.op(operation);
            (operation.opcode, operation.inputs.clone(), operation.output)
        };
        let output = output?;
        let output_size = data.varnode(output).size;
        let result = match inputs.as_slice() {
            [input] => {
                if data.varnode(*input).flags.constant {
                    return None;
                }
                if !self.pull_back_unary(opcode, data.varnode(*input).size, output_size) {
                    return None;
                }
                *input
            }
            [first, second] => {
                let (slot, result, constant) = if data.varnode(*first).flags.constant {
                    (1, *second, *first)
                } else if data.varnode(*second).flags.constant {
                    (0, *first, *second)
                } else {
                    return None;
                };
                if data.varnode(result).flags.constant {
                    return None;
                }
                if !self.pull_back_binary(
                    opcode,
                    data.varnode(constant).offset,
                    slot,
                    data.varnode(result).size,
                    output_size,
                ) {
                    // Ghidra has a SUBPIECE/NZMASK escape hatch here.  The
                    // graph exposes the same cached nonzero mask, so it can be
                    // represented without the C++ heritage machinery.
                    if !(use_nz_mask
                        && opcode == op::SUBPIECE
                        && data.varnode(constant).offset == 0)
                    {
                        return None;
                    }
                    let nonzero = data.nonzero_masks()[result.0 as usize];
                    let most_significant =
                        most_significant_bit(nonzero).map_or(0, |bit| (bit + 8) / 8);
                    if output_size < most_significant {
                        return None;
                    }
                    self.mask = calc_mask(data.varnode(result).size);
                }
                result
            }
            _ => return None,
        };

        if use_nz_mask {
            let nonzero = data.nonzero_masks()[result.0 as usize];
            let mut nz_range = Self::new();
            if nz_range.set_nz_mask(nonzero, data.varnode(result).size) {
                // A two-piece intersection retains the successful pullback,
                // exactly as CircleRange::pullBack does in rangeutil.cc:1075-1081.
                let _ = self.intersect(&nz_range);
            }
        }
        Some(result)
    }

    /// Translate this range into an integer comparison and its constant.
    ///
    /// Returns `(opcode, constant, constant_slot)` for a representable
    /// comparison, or `None` for empty, full, strided, or otherwise
    /// unrepresentable ranges.  This is `CircleRange::translate2Op` from
    /// `rangeutil.cc:1424-1467` and `rangeutil.hh:101`.
    pub fn translate2_op(&self) -> Option<(i32, u64, usize)> {
        if self.isempty || self.step != 1 {
            return None;
        }
        if self.right == self.left.wrapping_add(1) & self.mask {
            return Some((op::INT_EQUAL, self.left, 0));
        }
        if self.left == self.right.wrapping_add(1) & self.mask {
            return Some((op::INT_NOTEQUAL, self.right, 0));
        }
        if self.left == self.right {
            return None;
        }
        if self.left == 0 {
            return Some((op::INT_LESS, self.right, 1));
        }
        if self.right == 0 {
            return Some((op::INT_LESS, self.left.wrapping_sub(1) & self.mask, 0));
        }
        let sign_boundary = (self.mask >> 1).wrapping_add(1);
        if self.left == sign_boundary {
            return Some((op::INT_SLESS, self.right, 1));
        }
        if self.right == sign_boundary {
            return Some((op::INT_SLESS, self.left.wrapping_sub(1) & self.mask, 0));
        }
        None
    }

    fn complement(&mut self) {
        if self.isempty {
            self.left = 0;
            self.right = 0;
            self.isempty = false;
        } else if self.left == self.right {
            self.isempty = true;
        } else {
            std::mem::swap(&mut self.left, &mut self.right);
        }
    }

    fn convert_to_boolean(&mut self) -> bool {
        if self.isempty {
            return false;
        }
        let contains_zero = self.contains(0);
        let contains_one = self.contains(1);
        self.mask = 0xff;
        self.step = 1;
        if contains_zero && contains_one {
            self.left = 0;
            self.right = 2;
            self.isempty = false;
            true
        } else if contains_zero {
            self.left = 0;
            self.right = 1;
            self.isempty = false;
            false
        } else if contains_one {
            self.left = 1;
            self.right = 2;
            self.isempty = false;
            false
        } else {
            self.isempty = true;
            false
        }
    }

    fn new_stride(
        mask: u64,
        step: u32,
        old_step: u32,
        remainder: u64,
        left: &mut u64,
        right: &mut u64,
    ) -> bool {
        if old_step != 1 {
            let old_remainder = *left % u64::from(old_step);
            if old_remainder != remainder % u64::from(old_step) {
                return true;
            }
        }
        let original_order = *left < *right;
        let left_remainder = *left % u64::from(step);
        let right_remainder = *right % u64::from(step);
        if left_remainder > remainder {
            *left = left
                .wrapping_add(remainder)
                .wrapping_add(u64::from(step))
                .wrapping_sub(left_remainder);
        } else {
            *left = left.wrapping_add(remainder).wrapping_sub(left_remainder);
        }
        if right_remainder > remainder {
            *right = right
                .wrapping_add(remainder)
                .wrapping_add(u64::from(step))
                .wrapping_sub(right_remainder);
        } else {
            *right = right.wrapping_add(remainder).wrapping_sub(right_remainder);
        }
        *left &= mask;
        *right &= mask;
        original_order != (*left < *right)
    }

    fn new_domain(new_mask: u64, new_step: u32, left: &mut u64, right: &mut u64) -> bool {
        let remainder = if new_step != 1 {
            *left % u64::from(new_step)
        } else {
            0
        };
        if *left > new_mask {
            if *right > new_mask {
                if *left < *right {
                    return true;
                }
                *left = remainder;
                *right = remainder;
                return false;
            }
            *left = remainder;
        }
        if *right > new_mask {
            *right = remainder;
        }
        if *left == *right {
            *left = remainder;
            *right = remainder;
        }
        false
    }

    fn encode_range_overlaps(left: u64, right: u64, other_left: u64, other_right: u64) -> char {
        let mut value = if left <= right { 0x20 } else { 0 };
        if left <= other_left {
            value |= 0x10;
        }
        if left <= other_right {
            value |= 0x08;
        }
        if right <= other_left {
            value |= 0x04;
        }
        if right <= other_right {
            value |= 0x02;
        }
        if other_left <= other_right {
            value |= 0x01;
        }
        OVERLAP_ARRANGE[value] as char
    }
}

#[cfg(test)]
mod tests {
    use super::super::{Funcdata, SeqNum};
    use super::*;
    use ventris_lifter::REGISTER_SPACE;

    #[test]
    fn intersect_overlapping_and_disjoint_ranges() {
        let mut overlap = CircleRange::from_bounds(2, 10, 1, 1);
        let other = CircleRange::from_bounds(6, 14, 1, 1);
        assert_eq!(overlap.intersect(&other), 0);
        assert_eq!(overlap.get_min(), 6);
        assert_eq!(overlap.get_end(), 10);
        assert!(overlap.contains(6));
        assert!(!overlap.contains(10));

        let mut disjoint = CircleRange::from_bounds(2, 4, 1, 1);
        let other = CircleRange::from_bounds(6, 8, 1, 1);
        assert_eq!(disjoint.intersect(&other), 0);
        assert!(disjoint.is_empty());
        let mut wrapped_disjoint = CircleRange::from_bounds(12, 3, 1, 1);
        let other = CircleRange::from_bounds(5, 8, 1, 1);
        assert_eq!(wrapped_disjoint.intersect(&other), 0);
        assert!(wrapped_disjoint.is_empty());
    }

    #[test]
    fn intersect_handles_wrapped_ranges() {
        let mut wrapped = CircleRange::from_bounds(12, 3, 1, 1);
        let other = CircleRange::from_bounds(0, 2, 1, 1);
        assert_eq!(wrapped.intersect(&other), 0);
        assert_eq!(wrapped.get_min(), 0);
        assert_eq!(wrapped.get_end(), 2);
        assert!(wrapped.contains(0));
        assert!(wrapped.contains(1));
        assert!(!wrapped.contains(5));
    }

    #[test]
    fn circle_union_overlapping_disjoint_and_wrapped_ranges() {
        let mut overlap = CircleRange::from_bounds(2, 8, 1, 1);
        let other = CircleRange::from_bounds(6, 12, 1, 1);
        assert_eq!(overlap.circle_union(&other), 0);
        assert_eq!(overlap.get_min(), 2);
        assert_eq!(overlap.get_end(), 12);

        let mut disjoint = CircleRange::from_bounds(2, 4, 1, 1);
        let other = CircleRange::from_bounds(6, 8, 1, 1);
        assert_eq!(disjoint.circle_union(&other), 2);
        assert_eq!(disjoint.get_min(), 2);
        assert_eq!(disjoint.get_end(), 4);

        let mut wrapped = CircleRange::from_bounds(12, 3, 1, 1);
        let other = CircleRange::from_bounds(1, 6, 1, 1);
        assert_eq!(wrapped.circle_union(&other), 0);
        assert_eq!(wrapped.get_min(), 12);
        assert_eq!(wrapped.get_end(), 6);
        let mut wrapped_disjoint = CircleRange::from_bounds(12, 3, 1, 1);
        let other = CircleRange::from_bounds(5, 8, 1, 1);
        assert_eq!(wrapped_disjoint.circle_union(&other), 2);
        assert_eq!(wrapped_disjoint.get_min(), 12);
        assert_eq!(wrapped_disjoint.get_end(), 3);
    }

    #[test]
    fn constructors_stride_size_and_containment_follow_circle_model() {
        let mut normalized = CircleRange::from_bounds(3, 3, 1, 2);
        normalized.normalize();
        assert_eq!(normalized.get_min(), 1);
        assert_eq!(normalized.get_size(), 128);
        assert!(normalized.contains(3));
        assert!(!normalized.contains(2));

        let mut ranged = CircleRange::new();
        ranged.set_range(2, 10, 1, 1);
        ranged.set_stride(2, 0);
        assert_eq!(ranged.get_size(), 4);
        assert_eq!(ranged.get_max(), 8);
        assert!(ranged.contains_range(&CircleRange::from_bounds(4, 8, 1, 2)));
        assert!(!ranged.contains_range(&CircleRange::from_bounds(3, 8, 1, 1)));

        let mut singleton = CircleRange::new();
        singleton.set_value(255, 1);
        assert!(singleton.is_single());
        assert_eq!(singleton.get_max(), 255);
        let mut value = 255;
        assert!(!singleton.get_next(&mut value));

        let mut full = CircleRange::new();
        full.set_full(1);
        assert!(full.is_full());
        assert_eq!(full.get_size(), 256);

        let mut masked = CircleRange::new();
        assert!(masked.set_nz_mask(0xfc, 1));
        assert_eq!(masked.get_step(), 4);
        assert!(masked.contains(8));
        assert!(!masked.contains(2));
    }

    #[test]
    fn pull_back_integer_less_than_constant() {
        let mut range = CircleRange::from_bool(true);
        assert!(range.pull_back_binary(op::INT_LESS, 7, 0, 1, 1));
        assert_eq!(range.get_mask(), 0xff);
        assert_eq!(range.get_min(), 0);
        assert_eq!(range.get_end(), 7);
        assert!(range.contains(0));
        assert!(range.contains(6));
        assert!(!range.contains(7));
    }

    #[test]
    fn pull_back_boolean_negate() {
        let mut range = CircleRange::from_bool(true);
        assert!(range.pull_back_unary(op::BOOL_NEGATE, 1, 1));
        assert_eq!(range.get_min(), 0);
        assert_eq!(range.get_end(), 1);
        assert!(range.contains(0));
        assert!(!range.contains(1));
    }

    #[test]
    fn translate_single_and_interval_ranges() {
        let single = CircleRange::from_value(9, 1);
        assert_eq!(single.translate2_op(), Some((op::INT_EQUAL, 9, 0)));
        let interval = CircleRange::from_bounds(0, 9, 1, 1);
        assert_eq!(interval.translate2_op(), Some((op::INT_LESS, 9, 1)));
    }
    #[test]
    fn pull_back_graph_int_less_returns_unknown_input() {
        let mut data = Funcdata::default();
        let block = data.new_block(0x1000);
        let input = data.new_varnode(REGISTER_SPACE, 0, 1);
        data.mark_input(input);
        let constant = data.new_constant(7, 1);
        let operation = data.new_op(
            op::INT_LESS,
            SeqNum {
                address: 0x1000,
                order: 0,
            },
            vec![input, constant],
        );
        let output = data.new_unique(1);
        data.op_set_output(operation, Some(output));
        data.op_insert_end(operation, block);

        let mut range = CircleRange::from_bool(true);
        assert_eq!(range.pull_back(&data, operation, false), Some(input));
        assert_eq!(range.get_min(), 0);
        assert_eq!(range.get_end(), 7);
    }

    #[test]
    fn pull_back_graph_bool_negate_returns_unknown_input() {
        let mut data = Funcdata::default();
        let block = data.new_block(0x1000);
        let input = data.new_varnode(REGISTER_SPACE, 0, 1);
        data.mark_input(input);
        let operation = data.new_op(
            op::BOOL_NEGATE,
            SeqNum {
                address: 0x1000,
                order: 0,
            },
            vec![input],
        );
        let output = data.new_unique(1);
        data.op_set_output(operation, Some(output));
        data.op_insert_end(operation, block);

        let mut range = CircleRange::from_bool(true);
        assert_eq!(range.pull_back(&data, operation, false), Some(input));
        assert_eq!(range.get_min(), 0);
        assert_eq!(range.get_end(), 1);
    }
}
