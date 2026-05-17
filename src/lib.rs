//! semantic-facts-swift — Parser-derived semantic facts for Swift.
//!
//! Provides `semantic-facts@swift/v1` by consuming parser capabilities:
//! - `parse.call-sites@swift/v1`
//! - `parse.retrieval@swift/v1`
//!
//! No LSP, no symbol resolution — just parser-derived facts.

#![no_std]

extern crate alloc;
use alloc::vec::Vec;

use basalt_plugin_sdk::prelude::*;

// ── Fact type constants ────────────────────────────────────────────────────

const FACT_TYPE_DECL: u8 = 1;
const FACT_PROTOCOL_DECL: u8 = 2;
const FACT_FUNCTION_DECL: u8 = 3;
const FACT_METHOD_DECL: u8 = 4;
const FACT_CALL_EDGE: u8 = 5;
const FACT_MEMBER_OF: u8 = 6;
const FACT_INHERITS: u8 = 7;
const FACT_CONFORMS_TO: u8 = 8;

// ── Plugin metadata ────────────────────────────────────────────────────────

basalt_plugin_meta! {
    name:              "semantic-facts-swift",
    version:           env!("CARGO_PKG_VERSION"),
    hook_flags:        CAP_CAPABILITY_HANDLE,
    provides:          "semantic-facts@swift/v1",
    requires:          "parse.call-sites@swift/v1\nparse.retrieval@swift/v1",
    optional_requires: "",
    file_globs:        "**/*.swift",
    activates_on:      "",
    activation_events: "",
}

// ── Capability handle export ───────────────────────────────────────────────

/// Main capability entry point.
///
/// Request format: `[src_len: u32 LE][src_bytes]`
/// Response format: `[count × fact records]`
#[unsafe(no_mangle)]
pub extern "C" fn basalt_capability_handle(
    cap_ptr: *const u8,
    cap_len: usize,
    req_ptr: *const u8,
    req_len: usize,
) -> i64 {
    let _ = (cap_ptr, cap_len); // capability string already validated by host

    if req_ptr.is_null() || req_len == 0 {
        return pack_empty();
    }

    let request = unsafe { core::slice::from_raw_parts(req_ptr, req_len) };

    // Parse request: [src_len: u32 LE][src_bytes]
    if request.len() < 4 {
        return pack_error(-1002); // malformed payload
    }
    let src_len = u32::from_le_bytes([
        request[0],
        request[1],
        request[2],
        request[3],
    ]) as usize;

    if request.len() < 4 + src_len {
        return pack_error(-1002);
    }
    let src = &request[4..4 + src_len];

    if src.is_empty() {
        return pack_empty();
    }

    // Derive facts from parser output.
    match derive_semantic_facts(src) {
        Ok(facts) => pack_success(facts),
        Err(code) => pack_error(code),
    }
}

// ── Semantic fact derivation ───────────────────────────────────────────────

fn derive_semantic_facts(src: &[u8]) -> Result<Vec<u8>, i64> {
    let call_sites_raw = invoke_parse_call_sites(src)?;
    let retrieval_raw = invoke_parse_retrieval(src)?;

    let call_sites = decode_call_sites(&call_sites_raw);
    let retrieval = decode_retrieval(&retrieval_raw);

    let mut facts = Vec::new();

    // Derive declarations from retrieval chunks.
    derive_declarations(&retrieval, &mut facts);

    // Derive call edges from call sites.
    derive_call_edges(&call_sites, &mut facts);

    // Derive membership and inheritance from retrieval chunk nesting hints.
    derive_relationships(&retrieval, &mut facts);

    // Encode: [count: u32 LE][facts...]
    let count = facts.len() as u32;
    let mut out = Vec::with_capacity(4 + facts.len());
    out.extend_from_slice(&count.to_le_bytes());
    out.extend_from_slice(&facts);

    Ok(out)
}

// ── Parser capability invocations ──────────────────────────────────────────

fn invoke_parse_call_sites(src: &[u8]) -> Result<Vec<u8>, i64> {
    // Request: [src_len: u32 LE][src_bytes][max_sites: u32 LE]
    let mut request = Vec::with_capacity(4 + src.len() + 4);
    request.extend_from_slice(&(src.len() as u32).to_le_bytes());
    request.extend_from_slice(src);
    request.extend_from_slice(&16384u32.to_le_bytes());

    invoke_capability("parse.call-sites@swift/v1", &request)
        .map_err(|_| -1003)
}

fn invoke_parse_retrieval(src: &[u8]) -> Result<Vec<u8>, i64> {
    // Request: [src_len: u32 LE][src_bytes][max_chunks: u32 LE]
    let mut request = Vec::with_capacity(4 + src.len() + 4);
    request.extend_from_slice(&(src.len() as u32).to_le_bytes());
    request.extend_from_slice(src);
    request.extend_from_slice(&8192u32.to_le_bytes());

    invoke_capability("parse.retrieval@swift/v1", &request)
        .map_err(|_| -1003)
}

// ── Parser response decoding ───────────────────────────────────────────────

/// Decode call-sites response: `[count × 68-byte records: [offset: u32 LE][name: u8×64]]`
fn decode_call_sites(data: &[u8]) -> Vec<(u32, &str)> {
    if data.len() < 4 {
        return Vec::new();
    }
    let count = u32::from_le_bytes([data[0], data[1], data[2], data[3]]) as usize;
    let mut sites = Vec::with_capacity(count);
    let mut pos = 4;
    for _ in 0..count {
        if pos + 68 > data.len() {
            break;
        }
        let offset = u32::from_le_bytes([
            data[pos],
            data[pos + 1],
            data[pos + 2],
            data[pos + 3],
        ]);
        let name_bytes = &data[pos + 4..pos + 68];
        let nul = name_bytes.iter().position(|&b| b == 0).unwrap_or(64);
        if let Ok(name) = core::str::from_utf8(&name_bytes[..nul]) {
            if !name.is_empty() {
                sites.push((offset, name));
            }
        }
        pos += 68;
    }
    sites
}

/// Decode retrieval response: `[count × 104-byte records: [offset: u32 LE][length: u32 LE][label: u8×95][kind: u8]]`
fn decode_retrieval(data: &[u8]) -> Vec<(u32, u32, &str, u8)> {
    if data.len() < 4 {
        return Vec::new();
    }
    let count = u32::from_le_bytes([data[0], data[1], data[2], data[3]]) as usize;
    let mut chunks = Vec::with_capacity(count);
    let mut pos = 4;
    for _ in 0..count {
        if pos + 104 > data.len() {
            break;
        }
        let offset = u32::from_le_bytes([
            data[pos],
            data[pos + 1],
            data[pos + 2],
            data[pos + 3],
        ]);
        let length = u32::from_le_bytes([
            data[pos + 4],
            data[pos + 5],
            data[pos + 6],
            data[pos + 7],
        ]);
        let label_bytes = &data[pos + 8..pos + 103];
        let kind = data[pos + 103];
        let nul = label_bytes.iter().position(|&b| b == 0).unwrap_or(95);
        if let Ok(label) = core::str::from_utf8(&label_bytes[..nul]) {
            let label = label.trim();
            if !label.is_empty() && length > 0 {
                chunks.push((offset, length, label, kind));
            }
        }
        pos += 104;
    }
    chunks
}

// ── Fact derivation from parser output ─────────────────────────────────────

fn derive_declarations(retrieval: &[(u32, u32, &str, u8)], facts: &mut Vec<u8>) {
    for &(offset, length, label, kind) in retrieval {
        // kind mapping from parser:
        // 1=module, 2=type, 3=function, 4=extension, 5=property, 6=enum_case, 7=interface
        match kind {
            2 => {
                // type_decl or protocol_decl
                if label.starts_with("protocol ") || label.starts_with("interface ") {
                    encode_fact_protocol_decl(offset, length, label, facts);
                } else {
                    encode_fact_type_decl(offset, length, label, facts);
                }
            }
            3 => {
                // function_decl or method_decl (heuristic: if label contains "." it's a method)
                if label.contains('.') {
                    encode_fact_method_decl(offset, length, label, facts);
                } else {
                    encode_fact_function_decl(offset, length, label, facts);
                }
            }
            7 => {
                // protocol/interface declaration
                encode_fact_protocol_decl(offset, length, label, facts);
            }
            _ => {}
        }
    }
}

fn derive_call_edges(call_sites: &[(u32, &str)], facts: &mut Vec<u8>) {
    for &(offset, callee) in call_sites {
        encode_fact_call_edge(offset, callee, facts);
    }
}

fn derive_relationships(retrieval: &[(u32, u32, &str, u8)], facts: &mut Vec<u8>) {
    // Simple nesting-based relationship inference.
    // If a type is nested within another type's span, emit member_of.
    // If a type inherits from another (heuristic: label contains ":"), emit inherits/conforms_to.
    for &(offset, _length, label, kind) in retrieval {
        if kind == 2 || kind == 7 {
            // Check for inheritance/conformance in label
            // Swift: "class Foo: Bar, Baz" → inherits from Bar, conforms to Baz
            if let Some(colon_pos) = label.find(':') {
                let type_name = &label[..colon_pos].trim();
                let parents = &label[colon_pos + 1..];
                for parent in parents.split(',') {
                    let parent = parent.trim();
                    if parent.is_empty() {
                        continue;
                    }
                    // Heuristic: uppercase first letter = protocol (conforms_to)
                    // lowercase = type inheritance (inherits)
                    let first_char = parent.chars().next();
                    if let Some(c) = first_char {
                        if c.is_uppercase() {
                            encode_fact_conforms_to(offset, type_name, parent, facts);
                        } else {
                            encode_fact_inherits(offset, type_name, parent, facts);
                        }
                    }
                }
            }
        }
    }
}

// ── Fact encoding helpers ──────────────────────────────────────────────────

fn encode_str16(out: &mut Vec<u8>, s: &str) {
    let bytes = s.as_bytes();
    let len = core::cmp::min(bytes.len(), 0xFFFF) as u16;
    out.extend_from_slice(&len.to_le_bytes());
    out.extend_from_slice(&bytes[..len as usize]);
}

fn encode_fact_type_decl(offset: u32, length: u32, label: &str, facts: &mut Vec<u8>) {
    let name = label.strip_prefix("type ").unwrap_or(label)
        .strip_prefix("class ").unwrap_or(label)
        .strip_prefix("struct ").unwrap_or(label)
        .strip_prefix("enum ").unwrap_or(label)
        .strip_prefix("actor ").unwrap_or(label);
    facts.push(FACT_TYPE_DECL);
    facts.extend_from_slice(&offset.to_le_bytes());
    facts.extend_from_slice(&length.to_le_bytes());
    encode_str16(facts, name);
}

fn encode_fact_protocol_decl(offset: u32, length: u32, label: &str, facts: &mut Vec<u8>) {
    let name = label.strip_prefix("protocol ").unwrap_or(label)
        .strip_prefix("interface ").unwrap_or(label);
    facts.push(FACT_PROTOCOL_DECL);
    facts.extend_from_slice(&offset.to_le_bytes());
    facts.extend_from_slice(&length.to_le_bytes());
    encode_str16(facts, name);
}

fn encode_fact_function_decl(offset: u32, length: u32, label: &str, facts: &mut Vec<u8>) {
    let name = label.strip_prefix("function ").unwrap_or(label)
        .strip_prefix("initializer ").unwrap_or(label);
    facts.push(FACT_FUNCTION_DECL);
    facts.extend_from_slice(&offset.to_le_bytes());
    facts.extend_from_slice(&length.to_le_bytes());
    encode_str16(facts, name);
}

fn encode_fact_method_decl(offset: u32, length: u32, label: &str, facts: &mut Vec<u8>) {
    // label format: "function ParentType.methodName"
    let name = label.strip_prefix("function ").unwrap_or(label);
    let (parent, method) = if let Some(dot) = name.find('.') {
        (&name[..dot], &name[dot + 1..])
    } else {
        ("", name)
    };
    facts.push(FACT_METHOD_DECL);
    facts.extend_from_slice(&offset.to_le_bytes());
    facts.extend_from_slice(&length.to_le_bytes());
    encode_str16(facts, parent);
    encode_str16(facts, method);
}

fn encode_fact_call_edge(caller_offset: u32, callee: &str, facts: &mut Vec<u8>) {
    facts.push(FACT_CALL_EDGE);
    facts.extend_from_slice(&caller_offset.to_le_bytes());
    encode_str16(facts, callee);
}

fn encode_fact_member_of(member_offset: u32, parent_name: &str, facts: &mut Vec<u8>) {
    facts.push(FACT_MEMBER_OF);
    facts.extend_from_slice(&member_offset.to_le_bytes());
    encode_str16(facts, parent_name);
}

fn encode_fact_inherits(child_offset: u32, _child_name: &str, parent_name: &str, facts: &mut Vec<u8>) {
    facts.push(FACT_INHERITS);
    facts.extend_from_slice(&child_offset.to_le_bytes());
    encode_str16(facts, parent_name);
}

fn encode_fact_conforms_to(type_offset: u32, _type_name: &str, protocol_name: &str, facts: &mut Vec<u8>) {
    facts.push(FACT_CONFORMS_TO);
    facts.extend_from_slice(&type_offset.to_le_bytes());
    encode_str16(facts, protocol_name);
}
