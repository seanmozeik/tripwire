# Python and JavaScript write permissions

Tripwire previously treated normal writes as truncation unless it could prove that the output remained nonempty. This differed from the dedicated Write tool. It blocked ordinary JSON exports, file copies, regex edits, and Python `open(path, "w")` calls.

Normal writes now use the destination's Write policy. Empty content and overwrites are permitted on ordinary paths. Protected files such as `.env`, SSH material, and credential files remain blocked, including through existing and dangling symlinks. Relative paths use the tool call's working directory.

The analyzer still checks the whole submitted program. An allowed write cannot hide a separate delete, subprocess, or protected read. Explicit deletion and truncation APIs retain their safe-path requirements. A destination computed from unknown runtime data remains blocked with an unresolved-path diagnostic. This hook does not provide runtime filesystem containment.

Supported write forms include Python path/file writes, JSON file output, standard encoding keywords, Node writes and appends with supported options, and Deno text writes. Custom codecs, openers, callbacks, and arbitrary script files still require review. Ordinary overwrite recovery is outside this change; the Write tool has the same limitation.

Tests compare Python and JS decisions directly with the dedicated Write tool for normal, protected, relative, absolute, and symlink destinations. They also cover generated and empty data, regex changes, copied data, encoding options, unresolved paths, explicit deletion/truncation, and uninspected callbacks. All payloads are inert policy input. Sentinel files confirm that the tests do not execute submitted writes.
