<!-- SPDX-License-Identifier: GPL-2.0 -->
# Contributing to `mctp` tools

We have a few short guidelines for contributing to the `mctp` project, based
mainly on Linux kernel and OpenBMC conventions, as we have a reasonable
overlap with both.

In short:
 - Discuss major changes first
 - One change per commit, in general
 - Send contributions as PRs to our github repo
 - Add a Signed-off-by to indicate certification of the DCO
 - Include unit tests

Large or intrusive changes should be discussed first (ideally, before you have
code finalised) by opening a github issue. This generally saves time in
resolving design issues before implementation.

Issues or queries about the Linux kernel MCTP implementation (ie., related to
the MCTP stack itself, rather than the userspace tooling) should be filed
against the [CodeConstruct/linux](https://github.com/CodeConstruct/linux) repo.

Contributions should be submitted as pull-requests to our github repository at
<https://github.com/CodeConstruct/mctp>.

Contributions must be licensed under the GNU General Public License version 2,
or as otherwise indicated from the original source files. Newly added files
should include a SPDX-License-Identifier header, indicating `GPL-2.0`

## Structuring your changes

Commits should be as atomic as is sensible, by introducing one unit of change at
a time. Any updates as a result of PR review should be incorporated into the
original commits.

Commit messages should describe the rationale for the change, and an overview of
the change itself. There is no need to describe the actual code implementation,
we can review that in the diff itself. If there are points that may be useful
for the review process, but do not belong in permanent git history, include
those in the PR description.

We do not require a `Tested` section in commit messages.

Each commit message must include a `Signed-off-by` line, which indicates that
you (the contributor) have certified the [Developer Certificate of Origin
v1.1](https://developercertificate.org/) (DCO). This line must include the full
name you commonly use, often a given name and a family name or surname, and
should match the author metadata on the commit (ok: Sam Samuelsson, Robert A.
Heinlein; not ok: xXthorXx, Sam, RAH)

## Coding style

For C code, our coding style is generally that of the Linux kernel, and we
have a `.clang-format` definition to automate formatting.

For Python code (ie, the test framework), we use standard `ruff` formatting
settings.

## Tests

We have an extensive unit-test framework for `mctpd`, which provides mock kernel
interfaces and MCTP endpoints. We strongly encourage including tests with your
changes, typically as a separate patch in a contribution series.

## Coding assistants

We have a policy very similar to the kernel in regards to AI use in
contributions.

### Licensing and Legal Requirements

All contributions must comply with the project's licensing requirements,
using the overall GPLv2 license.

### Signed-off-by and Developer Certificate of Origin

AI agents MUST NOT add Signed-off-by tags. Only humans can legally
certify the Developer Certificate of Origin. The human submitter
is responsible for:

 * Reviewing all AI-generated code
 * Ensuring compliance with licensing requirements
 * Adding their own Signed-off-by tag to certify the DCO
 * Taking full responsibility for the contribution

### Attribution

When AI tools contribute to mctp development, proper attribution
helps track the evolving role of AI in the development process.
Contributions should include an Assisted-by tag in the following format:

    Assisted-by: AGENT_NAME:MODEL_VERSION [TOOL1] [TOOL2]

Where:

 * `AGENT_NAME` is the name of the AI tool or framework
 * `MODEL_VERSION` is the specific model version used
 * `[TOOL1] [TOOL2]` are optional specialized analysis tools used
    (e.g., coccinelle, sparse, smatch, clang-tidy)

Basic development tools (git, gcc, make, editors) should not be listed.

Example::

    Assisted-by: Claude:claude-3-opus coccinelle sparse
