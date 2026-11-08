# Public synthetic Go toolchain fixture

This directory contains newly authored **test-only** Go files. It is an
independent public CI diagnostic, not a copy or adaptation of a private
repository's source code. The tests use only the Go standard library and
constant, synthetic inputs. There are no external Go modules, machine
identifiers, credentials, event logs, monitoring rules, or configuration.

The workflow is **manual-only** (`workflow_dispatch`) and tests the availability
of Go 1.27 on standard hosted Windows 2022/2025 and Ubuntu 24.04 runners.
`actions/checkout` and `actions/setup-go` are pinned to verified Git commits;
no Go dependency cache is used. `GOPROXY` and `GOSUMDB` are disabled to reject
any unexpected module download. Checkout does not persist credentials.

A successful run would prove only that these public synthetic tests build and
run with Go 1.27 on the selected hosted runners. It would **not** validate
private Windows evidence collection, the target PC, or a forensic conclusion.
No private application code may be added without a separate publication review.
