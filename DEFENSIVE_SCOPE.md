# Defensive purpose and limits

Use this tool on local PDF artifacts you own or are authorized to inspect during
attachment triage, release review or incident evidence collection. It provides
reproducible name/structural observations before anyone opens the document in a
viewer. The runtime has no network, subprocess, package/plugin loading, JavaScript
execution, link access, archive handling, attachment extraction or file-writing
path. It does not generate bypass or executable document payloads.

Tests are inert dictionary/name/text/stream fixtures. Activity names have null or
empty values, so tests never require executable JavaScript or launched commands.
Bad-name/structure fixtures test parser boundaries and are never opened in a PDF
viewer. The scanner preserves input bytes.

PASS is restricted to the declared lexical checks. Semantic action reachability,
PDF conformance, xref/revision/object resolution, encryption, compressed streams
and viewer behavior remain unverified. Every report carries document safety and
action semantics as OPEN. Watched-name presence is an observation that merits
review; it is not proof of an action or maliciousness. Unrecognized content or
partial analysis cannot be called safe.
An observed lexical failure remains FAIL when diagnostic or report budgets are
reached. Command argument rejection reports only a fixed OPEN diagnostic; private
argument spellings and paths are not echoed in either output stream.

This is a lawful defensive artifact-inspection topic. CVP qualification is OPEN:
applicant identity/organization, attributable work, actual workflow and real
safeguards impact need separate truthful evidence. A project title, upstream
module, local tests or AI-assisted implementation cannot guarantee approval.
No production incident, viewer execution or application approval is claimed.
