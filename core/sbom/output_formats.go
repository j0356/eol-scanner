package sbom

// OutputFormat represents the SBOM output format
type OutputFormat string

const (
	FormatSyftJSON      OutputFormat = "syft-json"
	FormatSPDXJSON      OutputFormat = "spdx-json"
	FormatCycloneDXJSON OutputFormat = "cyclonedx-json"
)