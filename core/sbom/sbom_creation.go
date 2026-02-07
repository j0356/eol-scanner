package sbom

import (
	"context"
	"fmt"

	"github.com/anchore/stereoscope/pkg/image"
	"github.com/anchore/syft/syft"
	"github.com/anchore/syft/syft/format"
	"github.com/anchore/syft/syft/format/cyclonedxjson"
	"github.com/anchore/syft/syft/format/spdxjson"
	"github.com/anchore/syft/syft/format/syftjson"
	"github.com/anchore/syft/syft/sbom"
	"github.com/anchore/syft/syft/source"

	_ "modernc.org/sqlite" // Required for RPM database cataloging (registers as "sqlite")
)

// SourceType represents the type of image source
type SourceType string

const (
	// SourceTypeTar represents a local tar archive
	SourceTypeTar SourceType = "tar"
	// SourceTypeRegistry represents an image from a container registry
	SourceTypeRegistry SourceType = "registry"
	// SourceTypeDocker represents an image from the local Docker daemon
	SourceTypeDocker SourceType = "docker"
)

// RegistryCredentials holds authentication info for private registries
type RegistryCredentials struct {
	Authority  string // Registry host (e.g., "ghcr.io", "docker.io")
	Username   string
	Password   string
	Token      string // For token-based auth
	ClientCert string // For mTLS
	ClientKey  string // For mTLS
}

// ProgressCallback is called with status updates during SBOM generation
type ProgressCallback func(stage string, message string)

// Generator provides SBOM generation capabilities
type Generator struct {
	defaultFormat    OutputFormat
	credentials      []RegistryCredentials
	caFileOrDir      string
	progressCallback ProgressCallback
}

// NewGenerator creates a new SBOM generator
func NewGenerator() *Generator {
	return &Generator{
		defaultFormat: FormatSyftJSON,
	}
}

// WithDefaultFormat sets the default output format
// Possible input values: FormatSyftJSON (default), FormatSPDXJSON, FormatCycloneDXJSON
func (g *Generator) WithDefaultFormat(format OutputFormat) *Generator {
	g.defaultFormat = format
	return g
}

// WithCredentials adds registry credentials for private registries
func (g *Generator) WithCredentials(authority, username, password string) *Generator {
	g.credentials = append(g.credentials, RegistryCredentials{
		Authority: authority,
		Username:  username,
		Password:  password,
	})
	return g
}

// WithToken adds token-based authentication for a registry
func (g *Generator) WithToken(authority, token string) *Generator {
	g.credentials = append(g.credentials, RegistryCredentials{
		Authority: authority,
		Token:     token,
	})
	return g
}

// WithMTLS adds mTLS credentials for a registry
func (g *Generator) WithMTLS(authority, clientCert, clientKey string) *Generator {
	g.credentials = append(g.credentials, RegistryCredentials{
		Authority:  authority,
		ClientCert: clientCert,
		ClientKey:  clientKey,
	})
	return g
}

// WithCAFileOrDir sets custom CA certificates file or directory
func (g *Generator) WithCAFileOrDir(path string) *Generator {
	g.caFileOrDir = path
	return g
}

// WithProgress sets a callback for progress updates
func (g *Generator) WithProgress(callback ProgressCallback) *Generator {
	g.progressCallback = callback
	return g
}

// progress reports progress if a callback is set
func (g *Generator) progress(stage, message string) {
	if g.progressCallback != nil {
		g.progressCallback(stage, message)
	}
}

// GenerateFromTar creates an SBOM from a local tar archive
func (g *Generator) GenerateFromTar(ctx context.Context, tarPath string) (*sbom.SBOM, error) {
	return g.generate(ctx, tarPath)
}

// GenerateFromRegistry creates an SBOM from a container registry image
func (g *Generator) GenerateFromRegistry(ctx context.Context, imageRef string) (*sbom.SBOM, error) {
	return g.generate(ctx, imageRef)
}

// GenerateFromDocker creates an SBOM from a local Docker daemon image
func (g *Generator) GenerateFromDocker(ctx context.Context, imageRef string) (*sbom.SBOM, error) {
	return g.generate(ctx, imageRef)
}

// Generate creates an SBOM from any supported source type
func (g *Generator) Generate(ctx context.Context, sourceType SourceType, reference string) (*sbom.SBOM, error) {
	return g.generate(ctx, reference)
}

// generate is the internal method that handles SBOM generation
func (g *Generator) generate(ctx context.Context, reference string) (*sbom.SBOM, error) {
	cfg := g.buildSourceConfig()

	g.progress("source", fmt.Sprintf("Loading image: %s", reference))

	src, err := syft.GetSource(ctx, reference, cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to get source for %s: %w", reference, err)
	}
	defer src.Close()

	g.progress("catalog", "Cataloging packages...")

	result, err := syft.CreateSBOM(ctx, src, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create SBOM: %w", err)
	}

	g.progress("done", fmt.Sprintf("Found %d packages", result.Artifacts.Packages.PackageCount()))

	return result, nil
}

// buildSourceConfig creates the source configuration with authentication
func (g *Generator) buildSourceConfig() *syft.GetSourceConfig {
	cfg := syft.DefaultGetSourceConfig()

	if len(g.credentials) > 0 || g.caFileOrDir != "" {
		registryOpts := &image.RegistryOptions{
			CAFileOrDir: g.caFileOrDir,
		}

		for _, cred := range g.credentials {
			registryOpts.Credentials = append(registryOpts.Credentials, image.RegistryCredentials{
				Authority:  cred.Authority,
				Username:   cred.Username,
				Password:   cred.Password,
				Token:      cred.Token,
				ClientCert: cred.ClientCert,
				ClientKey:  cred.ClientKey,
			})
		}

		cfg = cfg.WithRegistryOptions(registryOpts)
	}

	return cfg
}

// FormatSBOM converts an SBOM to the specified format
func (g *Generator) FormatSBOM(s *sbom.SBOM, outputFormat OutputFormat) ([]byte, error) {
	encoder, err := g.getEncoder(outputFormat)
	if err != nil {
		return nil, err
	}

	return format.Encode(*s, encoder)
}

// FormatSBOMDefault converts an SBOM to the default format
func (g *Generator) FormatSBOMDefault(s *sbom.SBOM) ([]byte, error) {
	return g.FormatSBOM(s, g.defaultFormat)
}

// getEncoder returns the appropriate encoder for the output format
func (g *Generator) getEncoder(outputFormat OutputFormat) (sbom.FormatEncoder, error) {
	switch outputFormat {
	case FormatSyftJSON:
		return syftjson.NewFormatEncoder(), nil
	case FormatSPDXJSON:
		return spdxjson.NewFormatEncoderWithConfig(spdxjson.DefaultEncoderConfig())
	case FormatCycloneDXJSON:
		return cyclonedxjson.NewFormatEncoderWithConfig(cyclonedxjson.DefaultEncoderConfig())
	default:
		return nil, fmt.Errorf("unsupported output format: %s", outputFormat)
	}
}

// GetSource returns the underlying source for advanced use cases
func (g *Generator) GetSource(ctx context.Context, sourceType SourceType, reference string) (source.Source, error) {
	cfg := g.buildSourceConfig()
	return syft.GetSource(ctx, reference, cfg)
}
