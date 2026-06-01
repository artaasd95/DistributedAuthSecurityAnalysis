# Documentation Index

This folder contains the written material that supports the lab, including the technical report and the source references used to build it.

## Contents

- [report.tex](report.tex) - the LaTeX source for the technical report
- [report.pdf](report.pdf) - the compiled report, when generated locally
- [Phase 1 Theoretical Foundations of Modern Authentication and Authorization Protocols.pdf](Phase%201%20Theoretical%20Foundations%20of%20Modern%20Authentication%20and%20Authorization%20Protocols.pdf) - phase-specific deliverable for theoretical foundations
- [Phase 2 Laboratory Environment Design and Tool Specification.pdf](Phase%202%20Laboratory%20Environment%20Design%20and%20Tool%20Specification.pdf) - phase-specific deliverable for lab environment and tooling
- [Phase 3 Scenario Implementation and Attack Simulation.pdf](Phase%203%20Scenario%20Implementation%20and%20Attack%20Simulation.pdf) - phase-specific deliverable for implementation and attack workflow
- [Phase 4 Defensive Strategies and Infrastructure Hardening.pdf](Phase%204%20Defensive%20Strategies%20and%20Infrastructure%20Hardening.pdf) - phase-specific deliverable for mitigation and hardening
- [References/](References/) - standards, background reading, and source material used in the report

## Documentation Map

- Primary report authoring source: [report.tex](report.tex)
- Primary report output artifact: [report.pdf](report.pdf)
- Phase deliverables for milestone review: the four phase PDFs listed above
- Source standards and citations: [References/](References/)

## Recommended Reading Order

1. Start with [report.tex](report.tex) for the full technical narrative.
2. Review the phase PDFs for milestone-level summaries and checkpoints.
3. Review the files in [References/](References/) to trace protocol and security claims to source material.
4. Use [report.pdf](report.pdf) as the presentation-ready output when the PDF has been built.

## Building the Report

The repository does not require a custom build system for the report. Compile the LaTeX source with your preferred toolchain, for example `latexmk` or `pdflatex`, from the `Docs/` directory.

Example:

```text
cd Docs
latexmk -pdf report.tex
```

Alternative:

```text
cd Docs
pdflatex report.tex
```

## Documentation Quality Checklist

- Every new section in [report.tex](report.tex) cites or traces to source material in [References/](References/).
- Phase PDF updates remain consistent with the consolidated report.
- Terminology is consistent across OAuth 2.0, OIDC, JWT, PKCE, and RTR discussions.
- Security claims are backed by test evidence or standards references.

## Maintenance Notes

- Keep the report source and the reference material aligned when adding new sections.
- Prefer updating the source `.tex` file instead of editing the generated PDF directly.
- Store new reference material in [References/](References/) so the document structure stays consistent.

## Related Project Files

- Main project guide: [../README.md](../README.md)
- Contribution guide: [../CONTRIBUTING.md](../CONTRIBUTING.md)