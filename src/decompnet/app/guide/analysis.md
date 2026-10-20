# Analysis projects

An analysis project is any target REA can open — a native binary, an APK, a .NET assembly, a JavaScript app, a
firmware image, an archive — turned into the same project dashboard as a game. There is no compiler and no match
score. Each work item is a procedure, a regular file inside an archive, or a task the user added. An agent's job is
to understand it and leave a precise finding.

An archive project is one level of that: `claim_function()` gives you a file, `read_artifact_entry` reads it in place,
and `complete_function` records the finding. The user can analyze a binary or nested archive from **Contents** as a
linked child project; child findings are rolled into the parent's `SUMMARY.md`. Do not extract the whole archive or
open a child yourself: read the claimed entry within its limits.

## The loop

1. `claim_function()` gives you the next work item. For a procedure you get REA's dossier: signature, pseudocode,
   assembly, callers and referenced strings/names. For an archive file you get its path, size, type and the
   `read_artifact_entry` hint; for the `survey` item you get the target overview and memory map.
2. Read the dossier before calling more tools. It often answers the question on its own.
3. Go deeper with `rea_tool(tool, arguments)`. Useful tools:
   - `search_strings {"pattern": "..."}` and `search_procedures {"pattern": "..."}`: find things by name or text.
   - `analyze_function {"procedure": "0x401000"}`: a full dossier for any procedure.
   - `xrefs {"address": "0x..."}`: who references an address.
   - `procedure_callers` / `procedure_callees {"procedure": "..."}`: the local call graph.
   - `list_segments {}` and `read_bytes {"address": "0x...", "length": 64}`: memory layout and raw bytes.
   - `inspect_native_api {"procedure": "..."}`: imported Windows/Linux APIs and their arguments.
4. Write while you work: `add_note(text, function)` for anything the next agent should know.
5. Finish with `complete_function(function, summary)`. The summary is required: what the item does, its inputs and
   outputs, what it calls, the data it touches, and anything surprising. It is saved on the item and in the project's
   notes.
6. If the item is too large or needs a decision you can't make, `release_function(function, notes)` with what you
   tried and what is left.

## Tasks

The user can add a task without an address (for example "map the network protocol" or "find the update check"). A
task comes with the user's brief; follow it and finish with a summary. Tasks are not procedures, so `rea_tool` is
where the work happens.

## What counts as a good finding

- What the code does, in plain language, and where it sits in the program.
- Its contract: arguments, return value, side effects, error paths.
- The data it reads or writes, with addresses when they matter.
- Calls that identify the subsystem (network, files, crypto, UI) and any hard-coded strings or constants.
- Unknowns: say what you could not determine, and why (missing library, indirect call, stripped symbols).

Keep findings factual. Do not guess at a name or behavior you did not observe; say it is a hypothesis.
