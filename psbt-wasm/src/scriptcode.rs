//! The scriptCode a signature commits to, built the way Bitcoin Core's
//! interpreter builds it (src/script/interpreter.cpp: EvalScript,
//! EvalChecksigPreTapscript, OP_CHECKMULTISIG, FindAndDelete,
//! CTransactionSignatureSerializer::SerializeScriptCode) — so the verifier
//! can check a partial signature without a spending transaction.
//!
//! A partial signature has no execution path yet: which IF branches run is
//! decided by the scriptSig or witness that does not exist. What consensus
//! fixes is the shape: a signature check hashes from just past the last
//! OP_CODESEPARATOR that executed before it. This module enumerates every
//! start a path through the script's IF/NOTIF/ELSE/ENDIF structure can
//! produce for some signature-checking opcode, and nothing else, so "no
//! candidate verifies" is exactly "no execution accepts this signature" as
//! far as control flow decides it. (Stack values are not modelled: a branch
//! whose condition is forced, `1 IF`, still counts both ways. That only ever
//! adds candidates — the verifier stays silent rather than accuse a
//! signature some path accepts.)
//!
//! Per signature version:
//!   legacy   the scriptCode from the start, the signature removed by
//!            FindAndDelete (CHECKMULTISIG removes every signature it is
//!            given), OP_CODESEPARATOR opcodes skipped when serialized;
//!   BIP143   the scriptCode from the start, as is;
//!   tapscript the start's opcode position (BIP342 codesep_pos).

const OP_PUSHDATA1: u8 = 0x4c;
const OP_PUSHDATA2: u8 = 0x4d;
const OP_PUSHDATA4: u8 = 0x4e;
const OP_IF: u8 = 0x63;
const OP_NOTIF: u8 = 0x64;
const OP_ELSE: u8 = 0x67;
const OP_ENDIF: u8 = 0x68;
pub(crate) const OP_CODESEPARATOR: u8 = 0xab;
const OP_CHECKSIG: u8 = 0xac;
const OP_CHECKSIGVERIFY: u8 = 0xad;
const OP_CHECKMULTISIG: u8 = 0xae;
const OP_CHECKMULTISIGVERIFY: u8 = 0xaf;
const OP_CHECKSIGADD: u8 = 0xba;

/// BIP342 codesep_pos when no OP_CODESEPARATOR executed.
pub(crate) const NO_CODESEPARATOR: u32 = u32::MAX;

/// One opcode as Core's GetOp reads it at `pc`: the opcode byte and the
/// offset just past it and its push data. None at the end of the script or
/// when a push runs past it. Lengths are compared against the bytes left
/// rather than summed: on wasm32 a PUSHDATA4 length near 2^32 would wrap.
pub(crate) fn next_op(script: &[u8], pc: usize) -> Option<(u8, usize)> {
    let op = *script.get(pc)?;
    let left = script.len() - pc - 1;
    let (header, data_len) = match op {
        0x01..=0x4b => (0, op as usize),
        OP_PUSHDATA1 => (1, *script.get(pc + 1)? as usize),
        OP_PUSHDATA2 => (2, u16::from_le_bytes(script.get(pc + 1..pc + 3)?.try_into().ok()?) as usize),
        OP_PUSHDATA4 => (4, u32::from_le_bytes(script.get(pc + 1..pc + 5)?.try_into().ok()?) as usize),
        _ => (0, 0),
    };
    if data_len > left - header {
        return None;
    }
    Some((op, pc + 1 + header + data_len))
}

/// The script with OP_CODESEPARATOR opcodes removed, the way Core's
/// SerializeScriptCode writes a legacy scriptCode. Pushed data is copied
/// verbatim, separators inside it included. The walk ends at a truncated
/// push; such a script fails EvalScript, so no signature over it is valid
/// (`code_starts` reports it), and the bytes returned then are never used.
pub(crate) fn strip_codeseparators(script: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(script.len());
    let mut pc = 0;
    while let Some((op, end)) = next_op(script, pc) {
        if op != OP_CODESEPARATOR {
            out.extend_from_slice(&script[pc..end]);
        }
        pc = end;
    }
    out
}

/// `CScript() << data`: the push Core builds for a signature before
/// FindAndDelete looks for it. Direct pushes below 76 bytes, then
/// PUSHDATA1/2/4; an empty vector is the single byte 0x00.
pub(crate) fn push_encoding(data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(data.len() + 5);
    match data.len() {
        n if n < OP_PUSHDATA1 as usize => out.push(n as u8),
        n if n <= 0xff => out.extend_from_slice(&[OP_PUSHDATA1, n as u8]),
        n if n <= 0xffff => {
            out.push(OP_PUSHDATA2);
            out.extend_from_slice(&(n as u16).to_le_bytes());
        }
        n => {
            out.push(OP_PUSHDATA4);
            out.extend_from_slice(&(n as u32).to_le_bytes());
        }
    }
    out.extend_from_slice(data);
    out
}

/// Core's FindAndDelete: removes every occurrence of `pattern` that starts
/// on an opcode boundary, re-checking at the same boundary after each
/// removal (single pass: bytes that join up afterwards are not revisited).
/// A truncated push ends the walk and the rest is kept verbatim.
pub(crate) fn find_and_delete(script: &[u8], pattern: &[u8]) -> Vec<u8> {
    if pattern.is_empty() {
        return script.to_vec();
    }
    let mut result = Vec::with_capacity(script.len());
    let (mut pc, mut kept_from) = (0usize, 0usize);
    let mut found = false;
    loop {
        result.extend_from_slice(&script[kept_from..pc]);
        while script.len() - pc >= pattern.len() && script[pc..pc + pattern.len()] == *pattern {
            pc += pattern.len();
            found = true;
        }
        kept_from = pc;
        match next_op(script, pc) {
            Some((_, end)) => pc = end,
            None => break,
        }
    }
    if !found {
        return script.to_vec();
    }
    result.extend_from_slice(&script[kept_from..]);
    result
}

/// BIP66 strict DER (Core's IsValidSignatureEncoding) over the signature
/// with its hash type byte. Consensus since BIP66: any other non-empty
/// encoding fails the script. S is not required to be low (that is policy).
pub(crate) fn is_valid_signature_encoding(sig: &[u8]) -> bool {
    let len = sig.len();
    if !(9..=73).contains(&len) || sig[0] != 0x30 || sig[1] as usize != len - 3 {
        return false;
    }
    let len_r = sig[3] as usize;
    if 5 + len_r >= len {
        return false;
    }
    let len_s = sig[5 + len_r] as usize;
    if len_r + len_s + 7 != len {
        return false;
    }
    if sig[2] != 0x02 || len_r == 0 || sig[4] & 0x80 != 0 || (len_r > 1 && sig[4] == 0x00 && sig[5] & 0x80 == 0) {
        return false;
    }
    if sig[len_r + 4] != 0x02 || len_s == 0 || sig[len_r + 6] & 0x80 != 0 {
        return false;
    }
    !(len_s > 1 && sig[len_r + 6] == 0x00 && sig[len_r + 7] & 0x80 == 0)
}

/// Where one signature check's scriptCode can begin: `offset` is the byte
/// just past the OP_CODESEPARATOR (0 for none), `position` its opcode index
/// (NO_CODESEPARATOR for none). `multisig` when some CHECKMULTISIG can hash
/// from here — legacy FindAndDelete then removes its other signatures too.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct CodeStart {
    pub(crate) offset: usize,
    pub(crate) position: u32,
    pub(crate) multisig: bool,
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Shape {
    /// A push runs past the end: EvalScript fails on every path.
    Truncated,
    /// ELSE/ENDIF without IF, or IF without ENDIF: EvalScript fails on every
    /// path (pre-tapscript; tapscript is not judged, OP_SUCCESS comes first).
    Unbalanced,
    /// The starts some signature check can hash from, the no-separator start
    /// first when it is one. Empty when the script checks no signature.
    Starts(Vec<CodeStart>),
}

/// Fixed-size set of start indices (0 = no separator, k = the k-th one).
#[derive(Clone)]
struct Set(Vec<u64>);

impl Set {
    fn new(bits: usize) -> Self {
        Set(vec![0; bits.div_ceil(64)])
    }
    fn only(bits: usize, index: usize) -> Self {
        let mut set = Set::new(bits);
        set.0[index / 64] |= 1 << (index % 64);
        set
    }
    fn union(&mut self, other: &Set) {
        self.0.iter_mut().zip(&other.0).for_each(|(a, b)| *a |= b);
    }
    fn contains(&self, index: usize) -> bool {
        self.0[index / 64] & (1 << (index % 64)) != 0
    }
}

/// One IF block being walked: what flows out of the arms each condition
/// value runs (both start from the set on entry). Core's ELSE toggles, so
/// with several ELSEs a true condition runs arms 0, 2, 4… and a false one
/// arms 1, 3….
struct Frame {
    when_true: Set,
    when_false: Set,
    arm: usize,
}

/// The scriptCode starts of `script` (see `Shape`). The walk carries the set
/// of separators that can be the last one executed; a separator replaces
/// the set on its own arm, IF blocks fork it per condition value and join it
/// at ENDIF, and every signature-checking opcode marks the set it sees.
/// `tapscript` selects the opcodes that check signatures there
/// (CHECKSIGADD; CHECKMULTISIG is disabled) and skips the balance verdict.
pub(crate) fn code_starts(script: &[u8], tapscript: bool) -> Shape {
    let mut ops = Vec::new();
    let mut pc = 0;
    while pc < script.len() {
        let Some((op, end)) = next_op(script, pc) else { return Shape::Truncated };
        ops.push((op, end));
        pc = end;
    }
    let mut depth = 0usize;
    let mut balanced = true;
    for &(op, _) in &ops {
        match op {
            OP_IF | OP_NOTIF => depth += 1,
            OP_ELSE if depth == 0 => balanced = false,
            OP_ENDIF if depth == 0 => balanced = false,
            OP_ENDIF => depth -= 1,
            _ => {}
        }
    }
    balanced &= depth == 0;
    if !balanced && !tapscript {
        return Shape::Unbalanced;
    }

    let separators: Vec<(usize, usize)> = ops
        .iter()
        .enumerate()
        .filter(|(_, (op, _))| *op == OP_CODESEPARATOR)
        .map(|(position, &(_, end))| (position, end))
        .collect();
    let bits = separators.len() + 1;
    let mut reached = Set::new(bits);
    let mut multisig = Set::new(bits);
    let mut current = Set::only(bits, 0);
    let mut frames: Vec<Frame> = Vec::new();
    let mut next_separator = 1;
    for &(op, _) in &ops {
        match op {
            // Unbalanced tapscript: no structure to follow, so no separator
            // replaces the set — every one stays possible.
            OP_CODESEPARATOR if !balanced => {
                current.union(&Set::only(bits, next_separator));
                next_separator += 1;
            }
            OP_CODESEPARATOR => {
                current = Set::only(bits, next_separator);
                next_separator += 1;
            }
            OP_IF | OP_NOTIF if balanced => {
                frames.push(Frame { when_true: current.clone(), when_false: current.clone(), arm: 0 });
            }
            OP_ELSE if balanced => {
                let frame = frames.last_mut().expect("balanced");
                if frame.arm % 2 == 0 { frame.when_true = current } else { frame.when_false = current }
                frame.arm += 1;
                current = if frame.arm % 2 == 0 { frame.when_true.clone() } else { frame.when_false.clone() };
            }
            OP_ENDIF if balanced => {
                let mut frame = frames.pop().expect("balanced");
                if frame.arm % 2 == 0 { frame.when_true = current } else { frame.when_false = current }
                frame.when_true.union(&frame.when_false);
                current = frame.when_true;
            }
            OP_CHECKSIG | OP_CHECKSIGVERIFY => reached.union(&current),
            OP_CHECKSIGADD if tapscript => reached.union(&current),
            OP_CHECKMULTISIG | OP_CHECKMULTISIGVERIFY if !tapscript => {
                reached.union(&current);
                multisig.union(&current);
            }
            _ => {}
        }
    }
    let start = |index: usize| {
        let (offset, position) = if index == 0 { (0, NO_CODESEPARATOR) } else { (separators[index - 1].1, separators[index - 1].0 as u32) };
        CodeStart { offset, position, multisig: multisig.contains(index) }
    };
    Shape::Starts((0..bits).filter(|&index| reached.contains(index)).map(start).collect())
}

/// The most signature-shaped pushes a legacy multisig scriptCode may embed
/// and still be checked: every subset of them is a candidate scriptCode, and
/// 2^8 is the whole verification budget.
pub(crate) const MAX_MULTISIG_COMPANIONS: usize = 8;

/// The legacy scriptCodes one signature can be hashed with from `start`:
/// FindAndDelete of the signature's own push, and — when a CHECKMULTISIG
/// hashes from here — of the other signatures that multisig could be given.
/// Those are the canonical pushes left in the scriptCode that could be a
/// signature on its stack: strict-DER ones, and the empty push. Which of
/// them a spend deletes is fixed by the scriptSig, so every subset is a
/// candidate; None when there are more than MAX_MULTISIG_COMPANIONS, too
/// many subsets to try — the signature is then unchecked, not invalid.
/// Separators are stripped last, as the serializer does.
pub(crate) fn legacy_script_codes(script_code: &[u8], sig: &[u8], multisig: bool) -> Option<Vec<Vec<u8>>> {
    let own = find_and_delete(script_code, &push_encoding(sig));
    if !multisig {
        return Some(vec![strip_codeseparators(&own)]);
    }
    let mut others: Vec<Vec<u8>> = Vec::new();
    let mut pc = 0;
    while let Some((op, end)) = next_op(&own, pc) {
        if op <= OP_PUSHDATA4 {
            let header = match op { OP_PUSHDATA1 => 2, OP_PUSHDATA2 => 3, OP_PUSHDATA4 => 5, _ => 1 };
            let data = &own[pc + header..end];
            let push = &own[pc..end];
            let canonical = push_encoding(data) == push;
            if canonical && (data.is_empty() || is_valid_signature_encoding(data)) && !others.iter().any(|o| o == push) {
                others.push(push.to_vec());
            }
        }
        pc = end;
    }
    if others.len() > MAX_MULTISIG_COMPANIONS {
        return None;
    }
    let codes = (0u32..1 << others.len()).map(|mask| {
        let code = (0..others.len()).filter(|i| mask & (1 << i) != 0).fold(own.clone(), |code, i| find_and_delete(&code, &others[i]));
        strip_codeseparators(&code)
    });
    Some(codes.collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn h(text: &str) -> Vec<u8> {
        (0..text.len()).step_by(2).map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap()).collect()
    }

    #[test]
    fn strip_codeseparators_removes_opcodes_but_keeps_pushed_data() {
        // Bare opcodes go, everything else stays.
        assert_eq!(strip_codeseparators(&[0x51, 0xab, 0x52]), vec![0x51, 0x52]);
        // Separators inside a push are data, not opcodes.
        assert_eq!(strip_codeseparators(&[0x02, 0xab, 0xab, 0xab]), vec![0x02, 0xab, 0xab]);
        // PUSHDATA1 payloads are copied with their header.
        assert_eq!(strip_codeseparators(&[0x4c, 0x03, 0xab, 0x51, 0xab, 0x51]), vec![0x4c, 0x03, 0xab, 0x51, 0xab, 0x51]);
        // A truncated push ends the walk, as Core's GetOp failure does.
        assert_eq!(strip_codeseparators(&[0x51, 0x05, 0x52]), vec![0x51]);
        let mut plain = vec![0x76, 0xa9, 0x14];
        plain.extend_from_slice(&[0x11; 20]);
        plain.extend_from_slice(&[0x88, 0xac]);
        assert_eq!(strip_codeseparators(&plain), plain);
    }

    #[test]
    fn hostile_push_lengths_neither_wrap_nor_hang() {
        // PUSHDATA4 lengths near 2^32 (would wrap a 32-bit sum), truncated
        // PUSHDATA headers, and a length exactly one past the end.
        for script in [h("4efbffffff"), h("515151515151515151514ef6ffffff"), h("4c"), h("4d01"), h("4e010000"), h("4c02ab"), h("03abab")] {
            assert_eq!(code_starts(&script, false), Shape::Truncated, "{script:02x?}");
            let _ = strip_codeseparators(&script);
            let _ = find_and_delete(&script, &[0xab]);
        }
        assert_eq!(next_op(&h("4c02abab"), 0), Some((0x4c, 4)));
        assert_eq!(next_op(&[], 0), None);
    }

    /// Bitcoin Core's own FindAndDelete cases (src/test/script_tests.cpp,
    /// script_FindAndDelete, v31.1), expected results as Core states them.
    #[test]
    fn find_and_delete_matches_bitcoin_core() {
        for (script, pattern, expect) in [
            ("5152", "", "5152"),
            ("515253", "52", "5153"),
            ("535153535453", "53", "5154"),
            ("0302ff03", "0302ff03", ""),
            ("0302ff030302ff03", "0302ff03", ""),
            ("0302ff030302ff03", "02", "0302ff030302ff03"),
            ("0302ff030302ff03", "ff", "0302ff030302ff03"),
            ("0302ff030302ff03", "03", "02ff0302ff03"),
            ("02feed5169", "feed51", "02feed5169"),
            ("02feed5169", "02feed51", "69"),
            ("516902feed5169", "feed51", "516902feed5169"),
            ("516902feed5169", "02feed51", "516969"),
            ("00005151", "0051", "0051"),
            ("000051005151", "0051", "0051"),
            ("0003feed", "03feed", "00"),
            ("0003feed", "00", "03feed"),
        ] {
            assert_eq!(find_and_delete(&h(script), &h(pattern)), h(expect), "FindAndDelete({script}, {pattern})");
        }
    }

    #[test]
    fn push_encoding_is_cscript_operator_shift() {
        assert_eq!(push_encoding(&[]), vec![0x00]);
        assert_eq!(push_encoding(&[7; 75])[..1], [75]);
        assert_eq!(push_encoding(&[7; 76])[..2], [0x4c, 76]);
        assert_eq!(push_encoding(&[7; 256])[..3], [0x4d, 0x00, 0x01]);
        assert_eq!(push_encoding(&vec![7; 65536])[..5], [0x4e, 0x00, 0x00, 0x01, 0x00]);
    }

    /// BIP66's stated rules, one rejected case per rule, around the minimal
    /// valid signature r=1, s=1 (Core's tx_valid "shortest valid DER").
    #[test]
    fn strict_der_is_bip66() {
        let valid = h("300602010102010101");
        assert!(is_valid_signature_encoding(&valid));
        // A 33-byte R with its sign-guard zero, and a high S, are fine.
        assert!(is_valid_signature_encoding(&h(&format!("3026022100{}02010101", "80".repeat(32)))));
        assert!(is_valid_signature_encoding(&h(&format!("3026020101022100{}01", "ff".repeat(32)))));
        for (bad, rule) in [
            ("3006020101020101", "shorter than 9 bytes with the hash type"),
            (&format!("3047022100{}022200{}01", "81".repeat(32), "81".repeat(33))[..], "longer than 73 bytes"),
            ("310602010102010101", "not a compound 0x30"),
            ("300702010102010101", "total length does not cover the signature"),
            ("300603010102010101", "R is not an integer"),
            ("300602050102010101", "R length runs past the end"),
            ("300602000202010101", "R has zero length"),
            ("300602018102010101", "R is negative"),
            ("30070202000102010101", "R has a superfluous leading zero"),
            ("300602010103010101", "S is not an integer"),
            ("300602020101020001", "S has zero length"),
            ("300602010102018101", "S is negative"),
            ("30070201010202000101", "S has a superfluous leading zero"),
            ("300602010102020101", "S length runs past the end"),
        ] {
            let bad = h(&bad.replace(' ', ""));
            assert!(!is_valid_signature_encoding(&bad), "{rule}");
        }
    }

    fn starts(script: &str) -> Vec<(usize, u32, bool)> {
        match code_starts(&h(script), false) {
            Shape::Starts(starts) => starts.into_iter().map(|s| (s.offset, s.position, s.multisig)).collect(),
            other => panic!("{script}: {other:?}"),
        }
    }
    const K: &str = "21020202020202020202020202020202020202020202020202020202020202020202";

    #[test]
    fn a_top_level_separator_before_a_check_replaces_every_earlier_start() {
        // CODESEPARATOR <K> CHECKSIG: only past the separator.
        assert_eq!(starts(&format!("ab{K}ac")), vec![(1, 0, false)]);
        // <K> CHECKSIG CODESEPARATOR: the separator comes after the check.
        assert_eq!(starts(&format!("{K}acab")), vec![(0, NO_CODESEPARATOR, false)]);
        // <K> CHECKSIGVERIFY CODESEPARATOR <K> CHECKSIGVERIFY CODESEPARATOR 1:
        // one start per check (Core tx_valid "only if execution has reached it").
        assert_eq!(starts(&format!("{K}adab{K}adab51")), vec![(0, NO_CODESEPARATOR, false), (36, 2, false)]);
        // Two in a row: the second.
        assert_eq!(starts(&format!("abab{K}ac")), vec![(2, 1, false)]);
    }

    #[test]
    fn a_separator_inside_a_branch_is_one_possibility_among_others() {
        // IF CODESEPARATOR ENDIF <K> CHECKSIGVERIFY CODESEPARATOR 1
        assert_eq!(starts(&format!("63ab68{K}adab51")), vec![(0, NO_CODESEPARATOR, false), (2, 1, false)]);
        // IF CODESEPARATOR ELSE CODESEPARATOR ENDIF <K> CHECKSIG: one arm always runs.
        assert_eq!(starts(&format!("63ab67ab68{K}ac")), vec![(2, 1, false), (4, 3, false)]);
        // IF CODESEPARATOR ELSE ENDIF: the empty arm keeps the entry start.
        assert_eq!(starts(&format!("63ab6768{K}ac")), vec![(0, NO_CODESEPARATOR, false), (2, 1, false)]);
        // A check inside the branch sees only what reaches it there.
        assert_eq!(starts(&format!("ab63ab{K}ac68")), vec![(3, 2, false)]);
        // Nested: IF IF CODESEPARATOR ENDIF ELSE CODESEPARATOR ENDIF.
        assert_eq!(starts(&format!("6363ab6867ab68{K}ac")), vec![(0, NO_CODESEPARATOR, false), (3, 2, false), (6, 5, false)]);
        // Core's ELSE toggles: IF A ELSE B ELSE C ENDIF runs A and C, or B.
        // Separator in A only, C empty: a true condition keeps A's start.
        assert_eq!(starts(&format!("63ab676768{K}ac")), vec![(0, NO_CODESEPARATOR, false), (2, 1, false)]);
        // Separator in C only: true runs it, false (B) does not.
        assert_eq!(starts(&format!("636767ab68{K}ac")), vec![(0, NO_CODESEPARATOR, false), (4, 3, false)]);
        // Separators in A and B: whichever arm runs, one replaces the start.
        assert_eq!(starts(&format!("63ab67ab6768{K}ac")), vec![(2, 1, false), (4, 3, false)]);
    }

    #[test]
    fn multisig_starts_are_marked_and_scripts_without_checks_have_none() {
        assert_eq!(starts(&format!("52{K}{K}52ae")), vec![(0, NO_CODESEPARATOR, true)]);
        assert_eq!(starts(&format!("{K}acab52{K}{K}52af")), vec![(0, NO_CODESEPARATOR, false), (36, 2, true)]);
        assert_eq!(starts("ab5187"), vec![]);
        assert_eq!(starts(""), vec![]);
    }

    #[test]
    fn scripts_that_can_never_execute_are_named() {
        assert_eq!(code_starts(&h("68ac"), false), Shape::Unbalanced, "ENDIF without IF");
        assert_eq!(code_starts(&h("67ac"), false), Shape::Unbalanced, "ELSE without IF");
        assert_eq!(code_starts(&h("63ac"), false), Shape::Unbalanced, "IF without ENDIF");
        assert_eq!(code_starts(&h("51ab05ac"), false), Shape::Truncated);
    }

    #[test]
    fn tapscript_positions_count_every_opcode() {
        let tap = |script: &str| match code_starts(&h(script), true) {
            Shape::Starts(starts) => starts.into_iter().map(|s| s.position).collect::<Vec<_>>(),
            other => panic!("{other:?}"),
        };
        let x = format!("20{}", "02".repeat(32));
        assert_eq!(tap(&format!("ab{x}ac")), vec![0]);
        assert_eq!(tap(&format!("{x}abac")), vec![1]);
        assert_eq!(tap(&format!("{x}acab")), vec![NO_CODESEPARATOR]);
        assert_eq!(tap(&format!("{x}ab{x}ba51")), vec![1], "CHECKSIGADD checks a signature");
        assert_eq!(tap(&format!("ab{x}ae")), Vec::<u32>::new(), "CHECKMULTISIG checks nothing in tapscript");
        // Unbalanced tapscript is not judged here; every separator stays possible.
        assert_eq!(tap(&format!("ab68{x}ac")), vec![NO_CODESEPARATOR, 0]);
    }

    #[test]
    fn every_multisig_companion_subset_is_a_candidate_up_to_the_cap() {
        let sig = h("300602010102010101");
        // Distinct strict-DER pushes differing in S.
        let companion = |n: u8| push_encoding(&[0x30, 0x06, 0x02, 0x01, 0x02, 0x02, 0x01, n, 0x01]);
        let script_without = |count: u8, deleted: &[u8]| {
            [vec![0x52], (1..=count).filter(|n| !deleted.contains(n)).flat_map(|n| companion(n + 1)).collect(), h("52ae")].concat()
        };
        let script = |count: u8| script_without(count, &[]);
        assert_eq!(legacy_script_codes(&script(4), &sig, true).unwrap().len(), 16);
        // Five: all 32 subsets, intermediate ones included (a spend that
        // gives CHECKMULTISIG two of them deletes exactly those two).
        let codes = legacy_script_codes(&script(5), &sig, true).unwrap();
        assert_eq!(codes.len(), 32);
        for deleted in [&[][..], &[2, 4], &[1, 3, 5], &[1, 2, 3, 4], &[1, 2, 3, 4, 5]] {
            assert!(codes.contains(&script_without(5, deleted)), "{deleted:?}");
        }
        assert_eq!(legacy_script_codes(&script(MAX_MULTISIG_COMPANIONS as u8), &sig, true).unwrap().len(), 1 << MAX_MULTISIG_COMPANIONS);
        // Past the cap: not a partial list, no list.
        assert_eq!(legacy_script_codes(&script(MAX_MULTISIG_COMPANIONS as u8 + 1), &sig, true), None);
        // Without a multisig the companions are not deleted, however many.
        assert_eq!(legacy_script_codes(&script(9), &sig, false), Some(vec![script(9)]));
        // A non-DER push is never a companion; a repeated one counts once.
        let junk = [h("52"), push_encoding(&[0x30, 0x01]), companion(2), companion(2), h("52ae")].concat();
        assert_eq!(legacy_script_codes(&junk, &sig, true).unwrap().len(), 2);
    }

    #[test]
    fn an_empty_signature_is_a_companion_and_deletes_op_0() {
        // An empty signature on the multisig stack makes FindAndDelete remove
        // every OP_0 on an opcode boundary (Core pushes it as the byte 0x00).
        let sig = h("300602010102010101");
        assert_eq!(legacy_script_codes(&h("0051ae"), &sig, true), Some(vec![h("0051ae"), h("51ae")]));
        // Without a multisig nothing but the own signature is removed.
        assert_eq!(legacy_script_codes(&h("0051ac"), &sig, false), Some(vec![h("0051ac")]));
    }

    #[test]
    fn legacy_codes_delete_own_signature_and_multisig_companions() {
        let sig = h("300602010102010101");
        // <sig> SWAP CHECKSIG (Core tx_valid, shortest DER): the push goes.
        assert_eq!(legacy_script_codes(&h("093006020101020101017cac"), &sig, false), Some(vec![h("7cac")]));
        // A copy with another push prefix or hash type stays (Core tx_invalid).
        assert_eq!(legacy_script_codes(&h("ac4c09300602010102010101"), &sig, false), Some(vec![h("ac4c09300602010102010101")]));
        assert_eq!(legacy_script_codes(&h("ac09300602010102010181"), &sig, false), Some(vec![h("ac09300602010102010181")]));
        // Multisig: the other embedded signature may or may not be removed.
        let other = h("300602010202010201");
        let script = [h("52"), push_encoding(&other), h(&format!("{K}53ae"))].concat();
        let codes = legacy_script_codes(&script, &sig, true).unwrap();
        assert_eq!(codes, vec![script.clone(), [h("52"), h(&format!("{K}53ae"))].concat()]);
        // Separators are stripped after deletion.
        assert_eq!(legacy_script_codes(&h("ab093006020101020101017cac"), &sig, false), Some(vec![h("7cac")]));
    }
}
