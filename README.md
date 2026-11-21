# ADGraph Viewer

ADGraph Viewer is a database-free, browser-only viewer for BloodHound
JSON/ZIP collections. All collection data remains in memory in the current
browser tab. No dependencies need to be installed.

## Supported collectors

The viewer ingests the Active Directory JSON produced by the common BloodHound
collectors, both the legacy (BloodHound 4.x, data version 5) and Community
Edition (data version 6) families:

- **SharpHound** and **SharpHound CE**
- **bloodhound-python** and **bloodhound-ce-python**
- **RustHound** and **RustHound-CE**
- **Certipy** (`-bloodhound` / `-old-bloodhound`) for AD CS objects

It reads them uniformly: node/edge records use the same `ObjectIdentifier`,
`Properties`, `Aces`, and typed `ObjectIdentifier`/`ObjectType` references across
collectors. Differences between legacy and CE output are handled transparently —
CE's missing `highvalue` flags (see below), `ContainedBy` containment, and
CE-only collection files (`sites`, `siteservers`, `sitesubnets`) which are
recognised and skipped rather than reported as errors. Privileged built-in
groups (Domain Admins, Domain Controllers, …) are matched by well-known RID as
well as name, so renamed or localised domains still resolve.

Azure/Entra collections from AzureHound are a different graph model and are not
parsed by this viewer.

## Run

Open `index.html` directly in a modern browser. The application uses classic,
ordered browser scripts, so a local web server and build step are not required.

## AD CS escalation checks

The viewer works out common AD CS escalation conditions from a raw SharpHound
collection, without requiring BloodHound CE post-processing. After a collection
loads it derives clearly labelled "potential" relationships for ESC1, ESC2,
ESC3, ESC4, ESC6, ESC7, ESC9, ESC13, ESC15 and ESC16 from certificate-template
/ CA settings and enrollment ACLs (ESC7 from ManageCA / ManageCertificates or
full control over an enterprise CA; ESC16 when a CA disables the SID security
extension CA-wide). Each is marked `computed: true` (computed by the viewer),
keeps the raw inputs it was built from, and feeds the suggested attack paths the
same way the computed `DCSync` relationship does.

- Run **AD CS — Potential ESC (Viewer-Computed)** to list the derived
  relationships, or **AD CS — Computed ESC Paths** for BloodHound CE's own
  `ADCSESC*` edges. AD CS queries now explain when a dataset has nothing to show
  instead of returning an empty view.
- Select a certificate template or enterprise CA to see an **AD CS review** in
  the Inspector: the settings that matter, a pass/fail mark for each ESC
  condition, who can effectively enroll (template + CA enroll rights plus nested
  group membership), and defensive context — why each finding is risky, the
  Windows event IDs that show related certificate activity, and how to fix it.

## High-value targets (BloodHound CE collections)

Legacy SharpHound / bloodhound-python write a `highvalue` property, which the
viewer uses to pick attack-path targets. BloodHound CE collectors (SharpHound
CE, RustHound-CE) no longer emit it — Tier Zero is tagged server-side after
ingest — so a raw CE collection carries no high-value flags and **Suggested
Attack Paths would otherwise be empty**. When a collection has no high-value
flags at all, the viewer derives a default Tier Zero from well-known privileged
RIDs/SIDs (Domain/Enterprise/Schema Admins, built-in Administrators and operator
groups, the domain object, domain controllers, Administrator and krbtgt) so path
analysis still works. Collector-provided high-value flags always take precedence.

AD CS certificate-authority infrastructure (enterprise/root CAs, AIA CAs, the
NTAuth store, and the computer hosting the CA service) is **always** treated as
Tier Zero, because control of it is domain-equivalent (Golden Certificate /
ESC7) and collectors do not flag it. This lets certificate-services escalation
paths — e.g. a low-privileged principal that can take control of a CA — surface
in Suggested Attack Paths.

If nothing is marked Owned, path suggestions seed from broad groups (matched by
name and by RID) and roastable accounts; when none resolve (e.g. a collector
that omits primary-group membership), every enabled user is used as a
low-privilege starting assumption.

## Changes To Be Done

Currently, the tool just support files less than 256MB.
Another version is in progress, it'll be added under a new name depending on the requirement.

## Credits

Luke Arndt - MDSec ( for initial ideation and testing ) 
King Remy - MDSec ( for UI design and application flow )
Codex - For looking at issues and resolution.
