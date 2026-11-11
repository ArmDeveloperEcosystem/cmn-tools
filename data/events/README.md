# CMN PMU event files

Each `.events` file describes one CMN product and release. It maps the raw
event ID in `pmu_event_sel` to an event name and describes the selector
filter fields that affect that event, including their bit positions and widths.
Filter values in these files are the
unshifted values of the named hardware fields.

`A` records attach exact software event names and Linux `perf_event_open`
filter values to selected raw event and filter combinations. They are
optional: an event can be decoded from `E`/`U`/`V` without a named alias.

| File | Product and release |
| --- | --- |
| `cmn600-r3p2.events` | CMN-600 r3p2 |
| `cmn650-r2p0.events` | CMN-650 r2p0 |
| `cmn700-r0p0.events` | CMN-700 r0p0 |
| `cmn700-r3p0.events` | CMN-700 r3p0 |
| `cmns3-r2p2.events` | CMN S3 r2p2 |
| `cmns3-r5-package.events` | Baseline supplied in the CMN S3 r5 package |

Select the file for the device's product and release. The caller supplies
the node type, local PMU index, raw event ID, and either the full selector
register or unshifted values of its named filter fields. `F` records describe
filter positions within the full 64-bit `pmu_event_sel`. The caller remains
responsible for register offsets and event-slot extraction.

The PMU index identifies the 64-bit selector register relative to the node's
PMU base, in units of eight bytes. It is separate from the four event slots
inside each register. For example, on CMN S3 an HN-P exposes HN-I events
through PMU 0 at `0xD900`, and HN-P-specific events through PMU 1 at
`0xD908`. Both tables use reported node type `0x11`. See CMN S3 TRM
107858_0200_04_en, sections 8.3.12.43 and 8.3.12.44.

`cmn_events.py` selects the closest available release for the product,
comparing major revision distance first and patch distance second. Ties
prefer the older release. Without a device release it selects the newest
file. A `-r5-package` filename is treated as an r5 baseline with patch zero.
Legacy CSV files remain readable and provide a fallback path for products
without `.events` files.

`cmn_events.Events.decode_selector()` accepts the full, already-read
`pmu_event_sel` and extracts the used filters using the selected file's `F`
records. Callers can override these positions with an explicit field mapping.
When the file does not identify a field position, its value is
displayed as `?`; the decoder does not assume zero or select an alias for an
incomplete filter combination. Decoding does not read device registers.
The CMN S3 r5 package file does not specify HN-S filter positions and requires
an explicit field mapping for HN-S selector decoding.

## Syntax

Records are line oriented. Split each nonempty line on ASCII whitespace;
lines beginning with `#` are comments. Names and labels contain no spaces.
Numbers prefixed by `0x` are hexadecimal; other numbers are decimal. Record
order has no meaning. A field name in `F`, `U`, `V`, or `X` denotes the same
selector field within its node type.

| Record | Remaining fields | Meaning |
| --- | --- | --- |
| `N` | `reported_node_type canonical_node_type` | Use the canonical type for event lookup when the node reports the first type. |
| `M` | `node_type pmu_index event_id_mask` | Apply this mask to the raw event ID before lookup. With no `M` record, use the full raw ID. |
| `F` | `node_type pmu_index filter_field bit_position bit_width` | Position of the least significant bit and width of a hardware filter in the full 64-bit `pmu_event_sel`. Node type is canonical after `N` normalization. |
| `E` | `node_type pmu_index event_code event_name` | Event selection and its mnemonic. Code `0x0` is `none`. |
| `U` | `node_type pmu_index event_code filter_field` | The event uses this filter field. An event may have several `U` records. |
| `V` | `node_type filter_field raw_value label` | Display label for an unshifted filter-field value. |
| `X` | `node_type pmu_index event_code filter_field raw_value no_count` | This event selection counts nothing when that field has this value. |
| `A` | `node_type pmu_index raw_event_id software_name perf_filter perf_filter2 [filter_field=raw_value ...]` | Exact software name and perf mapping for one complete raw filter combination. Use `-` when a perf filter argument is absent. |

`F` definitions are unique by `(node_type, pmu_index, filter_field)`. Fields
within a PMU must not overlap or extend outside bits `[63:0]`, and widths
must be positive. An omitted `F` leaves the position unknown; named raw
filter values can still be decoded through `U` and `V`. Linux perf filter
arguments are separate values and do not define these positions.

An `A` record's `filter_field=raw_value` tokens name **hardware** fields.
They must name each `U` field for that event exactly once, including fields
set to zero. For an event without `U` fields, no such tokens are present.
Normalize `raw_event_id` through `M` to find its `E` record, but retain
the unmasked value as the Linux `eventid` argument. This preserves named
raw aliases such as CXHA `eventid=0x21`, which its event decoder treats
as code `0x01`.
The `A` node type is the canonical type after `N` normalization.
`perf_filter` and `perf_filter2` are the unshifted values passed as Linux
`filter` and `filter2` attributes; they are not register bit positions.
For a filtered event, `0x0` is a real value and differs from `-`.
Software names must be unique within a file. An `A` record does not make
unnamed hardware filter values invalid; it lists only a known software
name and its exact mapping. Verify the target driver's filter-argument
convention when using `A` records with more than one hardware filter;
the checked mapping is described in [DERIVATION.md](DERIVATION.md).
For an event with no `U` fields, its `E` mnemonic is also the default
software name, with the `E` code as Linux `eventid` and no perf filters.
An `A` record overrides this default when the software uses a different
raw event ID or name. For events with `U` fields, use `A` for exact
software names; `E` and `V` remain sufficient for hardware decoding.

## Decoding a selector

1. Replace the reported node type through `N`, if it has an alias.
2. Apply the `M` mask for that node type and PMU index, if present.
3. Find `E` by `(node_type, pmu_index, event_code)`. If there is no match,
   report an unknown selection for this file.
4. For each matching `U`, extract that field's raw value using its `F`
   position and width, or use a named raw value supplied by the caller.
   Use `V` to display a
   label where available, or display the numeric value. Ignore filter fields
   without a matching `U` for this event. Present multiple used fields in
   ascending bit-position order within `pmu_event_sel`; `U` record order
   has no meaning.
5. Check `X` for each used field and value. A match means the selected event
   is known but produces no count at that filter setting.
6. If an `A` record matches the raw event ID and complete tuple of used
   filter values, it supplies an exact software name. Otherwise retain the
   `E` name and `V` labels from step 4. For name-to-selector lookup, find
   `A` by `software_name` and use its raw event ID and hardware field
   values; its two perf columns give the Linux filter arguments. If no
   `A` matches, an unfiltered `E` can be used by its mnemonic.

For example, in `cmns3-r2p2.events`, HN-S event `0x07` with
`hbt_lbt_sel=0x2` and `evict_state_sel=0x5` decodes as
`hns_sf_evictions [hbt_lbt_sel=lbt, evict_state_sel=mu]`.
An alias such as
`A 0x200 0 0x7 hns_sf_evictions_lbt_mu 0x2 0x5 hbt_lbt_sel=0x2 evict_state_sel=0x5`
maps that exact combination to a software name and Linux filter arguments.

Filter fields are shared by the event slots in a selector register. Events
using the same field in those slots therefore see the same value. An `E`
record names an available event selection, subject to the node and ports
present in the device and any other PMU controls. An event with no `U`
records has no selector filters identified by this data.

XP/MXP event IDs encode event type in bits `[1:0]`, interface in `[4:2]`,
and channel in `[8:5]`. The XP names describe the usual multi-XP interface
mapping; a single-XP configuration can remap the interface field. Device
topology is needed to identify the physical port.

Release qualifications and supporting analysis are in
[DERIVATION.md](DERIVATION.md).
