# Python and JavaScript write permissions

Tripwire previously treated normal writes as truncation unless it could prove that the output remained nonempty. This differed from the dedicated Write tool. It blocked ordinary JSON exports, file copies, regex edits, and Python `open(path, "w")` calls.

Normal writes now use the destination's Write policy. Empty content and overwrites are permitted on ordinary paths. Protected files such as `.env`, SSH material, and credential files remain blocked, including through existing and dangling symlinks. Relative paths use the tool call's working directory.

The analyzer still checks the whole submitted program. An allowed write cannot hide a separate delete, subprocess, or protected read. Explicit deletion and truncation APIs retain their safe-path requirements. A destination computed from unknown runtime data remains blocked with an unresolved-path diagnostic. This hook does not provide runtime filesystem containment.

Supported write forms include Python path/file writes, JSON file output, standard encoding keywords, Node writes and appends with supported options, and Deno text writes. Custom codecs, openers, callbacks, and arbitrary script files still require review. Ordinary overwrite recovery is outside this change; the Write tool has the same limitation.

Tests compare Python and JS decisions directly with the dedicated Write tool for normal, protected, relative, absolute, and symlink destinations. They also cover generated and empty data, regex changes, copied data, encoding options, unresolved paths, explicit deletion/truncation, and uninspected callbacks. All payloads are inert policy input. Sentinel files confirm that the tests do not execute submitted writes.

## Transfers and working directories

Python `Path.rename`, `Path.replace`, `os.rename`, `os.replace`, `shutil.move`, copy functions, and symlink functions now emit the corresponding `mv`, `cp`, or `ln -s` policy operation. Node synchronous and promise APIs and Deno rename, copy, and symlink APIs use the same route. A move is not classified as an explicit delete. Shell and inline transfers check source access, destination writes, existing directory destinations, protected symlink targets, and configured command policies.

Relative deletion uses the tracked shell or interpreter cwd. A literal `cd /tmp` followed by `rm example.log` receives the same temporary-path classification as an absolute temporary target. Unknown shell operands and missing or dynamic working directories cannot gain permission from the safe cwd. Existing relative build-scope symlink confinement remains enforced.

Literal `Path.resolve` and `Path.readlink` share the filesystem resolution helper used by protected-path classification. Resolution after an earlier overlapping mutation, an unclassified subprocess, or an unknown cwd remains blocked. Missing readlink results remain opaque and cannot authorize file operands. These are hook-time checks; they do not establish runtime filesystem containment.
