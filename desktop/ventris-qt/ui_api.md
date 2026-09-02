# Ventris Qt UI API contract

Every `core_request` method the desktop frontend sends, in one place. The
Qt side must not call anything absent from this list; additions require a
bridge entry (`crates/lre-qt-bridge/src/lib.rs` `dispatch`) and a row here.

Wire envelope: request is `{"method": "<name>", ...params}`; the response is
`{"ok": true, "result": ...}` or `{"ok": false, "error": "<message>"}`.
Addresses arrive either as hex strings or as `{"offset": <int>}` objects
(see `json_util.h addressText`).

## Paging and revision semantics

- Paged methods (`functions_page`, `symbols_page`, `xrefs_page`) return
  `Page<T>`: `{"rows": [T], "offset": <int>, "total": <int>,
  "revision": <int>}`. `total` bounds the fetch-more loop; `revision` is
  the program's mutation epoch and changes whenever a command (rename,
  comment, patch, ...) lands. The UI displays it and refetches after
  mutations; it does not currently diff revisions.
- `decompile_doc` returns the program revision with the document; a stale
  document is detected by comparing against the current revision.
- Non-paged list methods (`strings`, `bookmarks`, `type_defs`, ...) return
  full arrays; they have no revision field and are refetched wholesale.

## Session

| Method | Request | Result |
| --- | --- | --- |
| `open` | `program` | program info |
| `import_native` | `binary`, `name` | program info |

## Functions

| Method | Request | Result |
| --- | --- | --- |
| `functions_page` | `program`, `offset`, `limit` | `Page<FunctionRow>`; row: `entry` (address), `name`, `size`, `signature` |

## Listing and decompilation

| Method | Request | Result |
| --- | --- | --- |
| `listing` | `binary`, `start`, `count` | `ListingWindow`: `rows` (`stable_id`, `address`, `text`), `start`, `count`, `overscan` |
| `decompile_doc` | `binary`, `program`, `address` | `DecompDoc`: `tokens` (`text`, `kind`, `color`, `symbol?`, `address?`, ...), `address`, `revision` |
| `memory` | `binary`, `address` (RAM only), `size` | `{"address", "size", "bytes_hex"}` |

## Facts

| Method | Request | Result |
| --- | --- | --- |
| `symbols_page` | `program`, `offset`, `limit` | `Page<SymbolRow>`; row: `name`, `address`, `external`, `source` |
| `strings` | `program` | `[StringRow]`: `address`, `value`, `kind` |
| `search` | `program`, `term`, `limit` | `[SearchHit]`: `address?`, `kind`, `name`, `context` |
| `xrefs_page` | `program`, `address`, `incoming`, `offset`, `limit` | `Page<XrefRow>`; row: `from`, `to`, `kind` |
| `memory_regions` | `program` | `[MemoryRegion]`: `name`, `start`, `size`, `permissions`, `source` |
| `function_graph` | `program` | `{"nodes": [{address, name}], "edges": [{from, to, kind}]}` |

## Commands (undoable, bump the revision)

| Method | Request | Result |
| --- | --- | --- |
| `rename` | `program`, `address`, `name` | `{"address", "name"}` |
| `comment` | `program`, `address`, `kind`, `text` | `{"address", "kind", "text"}` |
| `undo` | `program` | `{"message"}` |
| `set_patch` | `program`, `address`, `original` (bytes), `patched` (bytes), `enabled` | `{"address", "enabled"}` |

## Analyst data

| Method | Request | Result |
| --- | --- | --- |
| `bookmarks` | `program` | `[BookmarkRow]`: `address`, `label`, `comment` |
| `set_bookmark` | `program`, `bookmark {address, label, comment}` | `{"address", "label"}` |
| `patches` | `program` | `[PatchRow]`: `address`, `original`, `patched`, `enabled` |

## Trace and collaboration (experimental docks)

| Method | Request | Result |
| --- | --- | --- |
| `trace_events` | `program`, `since`, `limit` | `[TraceEvent]`: `sequence`, `at`, `thread`, `address?`, `kind`, `payload`, `provenance` |
| `collab_ops` | `program` | `[CollaborationOp]`: `op_id`, `actor`, `lamport`, `kind`, `payload`, `applied`, `provenance` |
| `append_collab_op` | `program`, `operation {op_id, actor, lamport, kind, payload, applied, provenance}` | `{"op_id", "inserted"}` |
| `apply_collab_op` | `program`, `op_id` | `{"op_id", "applied"}` |

## Types

| Method | Request | Result |
| --- | --- | --- |
| `type_defs` | `program` | `[TypeDefRow]`: `name`, `kind`, `definition`, `size?`, `alignment?`, `base_type?`, `provenance` |
| `type_fields` | `program` | `[TypeFieldRow]`: `type_name`, `ordinal`, `field_name`, `offset`, `size?`, `type_ref?` |
| `prototypes` | `program` | `[PrototypeRow]`: `function`, `signature`, `calling_convention?`, `return_type?` |
| `stack_variables` | `program` | `[StackVariableRow]`: `function`, `ordinal`, `name`, `storage`, `type_name?`, `offset?`, `size?` |
| `type_graph` | `program` | `{"nodes": [{name, kind, size?}], "edges": [{source, target, kind, provenance}]}` |
| `set_type_def` | `program`, `row` (TypeDefRow) | `{"name"}` |
| `set_type_field` | `program`, `row` (TypeFieldRow) | `{"type_name", "ordinal"}` |
| `set_prototype` | `program`, `row` (PrototypeRow) | `{"function"}` |
| `set_stack_variable` | `program`, `row` (StackVariableRow) | `{"function", "ordinal"}` |
| `propagate_type_links` | `program` | `[TypeLinkRow]`: `source`, `target`, `kind`, `provenance` |
