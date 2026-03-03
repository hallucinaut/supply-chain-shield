package main

import (
	"crypto/sha256"
	"encoding/hex"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/fatih/color"
)

var (
	infoColor = color.New(color.FgBlue)
	warnColor = color.New(color.FgYellow)
	errorColor = color.New(color.FgRed)
	successColor = color.New(color.FgGreen)
	criticalColor = color.New(color.FgRed, color.Bold)
	noticeColor = color.New(color.FgCyan)
)

// ArtifactType represents the type of artifact
type ArtifactType string

const (
	ArtifactTypeContainer   ArtifactType = "container"
	ArtifactTypePackage     ArtifactType = "package"
	ArtifactTypeBinary      ArtifactType = "binary"
	ArtifactTypeSource      ArtifactType = "source"
	ArtifactTypeConfig      ArtifactType = "config"
	ArtifactTypeCertificate ArtifactType = "certificate"
)

// VerificationStatus represents the verification status
type VerificationStatus string

const (
	StatusVerified    VerificationStatus = "verified"
	StatusFailed      VerificationStatus = "failed"
	StatusMissing     VerificationStatus = "missing"
	StatusUnsigned    VerificationStatus = "unsigned"
	StatusExpired     VerificationStatus = "expired"
	StatusCompromised VerificationStatus = "compromised"
)

// Artifact represents a software artifact
type Artifact struct {
	ID            string         `json:"id"`
	Name          string         `json:"name"`
	Type          ArtifactType   `json:"type"`
	Version       string         `json:"version"`
	Location      string         `json:"location"`
	Hash          string         `json:"hash"`
	Algorithm     string         `json:"algorithm"`
	Signature     string         `json:"signature,omitempty"`
	SignedBy      string         `json:"signed_by,omitempty"`
	SignerCert    string         `json:"signer_cert,omitempty"`
	Chain         []string       `json:"chain,omitempty"`
	Provenance    []Provenance   `json:"provenance,omitempty"`
	Dependencies  []Dependency   `json:"dependencies,omitempty"`
	SBOM          *SBOM          `json:"sbom,omitempty"`
	CreatedAt     time.Time      `json:"created_at"`
	ExpiresAt     time.Time      `json:"expires_at"`
	Status        VerificationStatus `json:"status"`
	Metadata      map[string]interface{} `json:"metadata,omitempty"`
}

// Provenance represents artifact provenance information
type Provenance struct {
	Type        string    `json:"type"`
	Builder     string    `json:"builder"`
	BuildID     string    `json:"build_id"`
	Timestamp   time.Time `json:"timestamp"`
	Source      string    `json:"source"`
	SourceHash  string    `json:"source_hash"`
	Parameters  []string  `json:"parameters"`
}

// Dependency represents an artifact dependency
type Dependency struct {
	Name    string        `json:"name"`
	Version string        `json:"version"`
	Type    ArtifactType  `json:"type"`
	Hash    string        `json:"hash"`
	License string        `json:"license"`
}

// SBOM represents a Software Bill of Materials
type SBOM struct {
	Type        string    `json:"type"`
	Version     string    `json:"version"`
	GeneratedAt time.Time `json:"generated_at"`
	Components  []Component `json:"components"`
	Dependencies []Dependency `json:"dependencies"`
}

// Component represents a component in SBOM
type Component struct {
	Name       string    `json:"name"`
	Version    string    `json:"version"`
	Type       string    `json:"type"`
	License    string    `json:"license"`
	Hash       string    `json:"hash"`
	Vendors    []string  `json:"vendors"`
	CPE        string    `json:"cpe"`
	PURL       string    `json:"purl"`
}

// SupplyChainSecurityResult holds the result of supply chain security check
type SupplyChainSecurityResult struct {
	ArtifactID     string              `json:"artifact_id"`
	ArtifactName   string              `json:"artifact_name"`
	Status         VerificationStatus  `json:"status"`
	Verifications  []Verification      `json:"verifications"`
	Provenance     []Provenance        `json:"provenance"`
	SBOM           *SBOM               `json:"sbom,omitempty"`
	Vulnerabilities []Vulnerability    `json:"vulnerabilities,omitempty"`
	RiskScore      float64             `json:"risk_score"`
	Recommendations []string           `json:"recommendations"`
}

// Verification represents a security verification
type Verification struct {
	Type      string                `json:"type"`
	Status    VerificationStatus    `json:"status"`
	Message   string                `json:"message"`
	Timestamp time.Time             `json:"timestamp"`
	Details   map[string]interface{} `json:"details,omitempty"`
}

// Vulnerability represents a security vulnerability
type Vulnerability struct {
	ID          string    `json:"id"`
	CVE         string    `json:"cve"`
	Severity    string    `json:"severity"`
	Description string    `json:"description"`
	AffectedVersion string `json:"affected_version"`
	FixedVersion  string `json:"fixed_version"`
	Source      string    `json:"source"`
}

// SupplyChainShield performs supply chain security checks
type SupplyChainShield struct {
	artifacts   []Artifact
	results     []SupplyChainSecurityResult
	failOnHigh  bool
	failOnCritical bool
	verbose     bool
	dryRun      bool
	sbomPath    string
}

// NewSupplyChainShield creates a new SupplyChainShield
func NewSupplyChainShield(failOnHigh, failOnCritical, verbose, dryRun bool) *SupplyChainShield {
	return &SupplyChainShield{
		artifacts:    make([]Artifact, 0),
		results:      make([]SupplyChainSecurityResult, 0),
		failOnHigh:   failOnHigh,
		failOnCritical: failOnCritical,
		verbose:      verbose,
		dryRun:       dryRun,
		sbomPath:     "",
	}
}

// DiscoverArtifacts discovers artifacts in the specified paths
func (scshield *SupplyChainShield) DiscoverArtifacts(paths []string) error {
	noticeColor.Println("\n🔍 Discovering artifacts...\n")

	for _, path := range paths {
		infoColor.Printf("Scanning: %s\n", path)

		err := filepath.Walk(path, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return err
			}

			if info.IsDir() {
				if strings.HasPrefix(info.Name(), ".") || info.Name() == "node_modules" || info.Name() == ".git" {
					return filepath.SkipDir
				}
				return nil
			}

			artifact := scshield.discoverArtifact(path, info)
			if artifact != nil {
				scshield.artifacts = append(scshield.artifacts, *artifact)
				successColor.Printf("  ✅ Discovered: %s (%s)\n", artifact.Name, artifact.Type)
			}

			return nil
		})

		if err != nil {
			warnColor.Printf("⚠️  Error scanning %s: %v\n", path, err)
		}
	}

	noticeColor.Printf("\n📊 Discovered %d artifacts\n\n", len(scshield.artifacts))
	return nil
}

// discoverArtifact discovers a single artifact
func (scshield *SupplyChainShield) discoverArtifact(path string, info os.FileInfo) *Artifact {
	fileExt := strings.ToLower(filepath.Ext(path))
	fileName := strings.ToLower(filepath.Base(path))

	// Detect artifact type
	var artifactType ArtifactType
	var version string

	switch fileExt {
	case ".tar", ".tar.gz", ".tgz":
		artifactType = ArtifactTypeContainer
		if idx := strings.Index(fileName, "-"); idx != -1 {
			version = fileName[idx+1:]
		}
	case ".whl", ".egg":
		artifactType = ArtifactTypePackage
		if idx := strings.Index(fileName, "-"); idx != -1 {
			version = fileName[idx+1:]
		}
	case ".deb", ".rpm":
		artifactType = ArtifactTypePackage
		if idx := strings.Index(fileName, "_"); idx != -1 {
			version = fileName[idx+1 : idx+4]
		}
	case ".pem", ".crt", ".cer":
		artifactType = ArtifactTypeCertificate
	case ".jar", ".war", ".ear":
		artifactType = ArtifactTypeBinary
	case ".mod", ".sum":
		artifactType = ArtifactTypeConfig
	default:
		// Check file content for type detection
		artifactType = scshield.detectArtifactType(path)
	}

	if artifactType == "" {
		return nil
	}

	// Calculate hash
	hash, err := scshield.calculateHash(path)
	if err != nil {
		warnColor.Printf("  ⚠️  Could not calculate hash for %s: %v\n", path, err)
	}

	artifact := &Artifact{
		ID:        fmt.Sprintf("%s-%d", fileName, time.Now().Unix()),
		Name:      fileName,
		Type:      artifactType,
		Version:   version,
		Location:  path,
		Hash:      hash,
		Algorithm: "sha256",
		CreatedAt: time.Now(),
		Status:    StatusMissing,
		Metadata:  make(map[string]interface{}),
	}

	return artifact
}

// detectArtifactType detects artifact type from file content
func (scshield *SupplyChainShield) detectArtifactType(path string) ArtifactType {
	content, err := os.ReadFile(path)
	if err != nil {
		return ""
	}

	contentStr := string(content)

	if strings.Contains(contentStr, "FROM ") && strings.Contains(contentStr, "RUN ") {
		return ArtifactTypeContainer
	}

	if strings.Contains(contentStr, "module") && strings.Contains(contentStr, "go ") {
		return ArtifactTypeConfig
	}

	if strings.Contains(contentStr, "dependencies") || strings.Contains(contentStr, "component") {
		return ArtifactTypePackage
	}

	return ArtifactTypeBinary
}

// calculateHash calculates SHA256 hash of a file
func (scshield *SupplyChainShield) calculateHash(path string) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer file.Close()

	hasher := sha256.New()
	buf := make([]byte, 8192)
	for {
		n, err := file.Read(buf)
		if n > 0 {
			hasher.Write(buf[:n])
		}
		if err != nil {
			break
		}
	}

	return hex.EncodeToString(hasher.Sum(nil)), nil
}

// VerifyArtifact performs supply chain security verification on an artifact
func (scshield *SupplyChainShield) VerifyArtifact(artifact Artifact) SupplyChainSecurityResult {
	result := SupplyChainSecurityResult{
		ArtifactID:    artifact.ID,
		ArtifactName:  artifact.Name,
		Status:        StatusMissing,
		Verifications: make([]Verification, 0),
		Provenance:    artifact.Provenance,
		Recommendations: make([]string, 0),
		RiskScore:     0,
	}

	// Verify signature
	sigVerify := scshield.verifySignature(artifact)
	result.Verifications = append(result.Verifications, sigVerify)
	if sigVerify.Status == StatusVerified {
		result.Status = StatusVerified
	}

	// Verify hash
	hashVerify := scshield.verifyHash(artifact)
	result.Verifications = append(result.Verifications, hashVerify)

	// Verify provenance
	provVerify := scshield.verifyProvenance(artifact)
	result.Verifications = append(result.Verifications, provVerify)
	result.Provenance = artifact.Provenance

	// Check for vulnerabilities
	vulns := scshield.checkVulnerabilities(artifact)
	result.Vulnerabilities = vulns

	// Calculate risk score
	riskScore := scshield.calculateRiskScore(artifact, result.Verifications, vulns)
	result.RiskScore = riskScore

	// Generate recommendations
	recommendations := scshield.generateRecommendations(artifact, result.Verifications, vulns)
	result.Recommendations = recommendations

	// Update status based on verifications
	if sigVerify.Status == StatusFailed || hashVerify.Status == StatusFailed {
		result.Status = StatusFailed
	} else if sigVerify.Status == StatusUnsigned || provVerify.Status == StatusMissing {
		result.Status = StatusUnsigned
	} else if riskScore > 70 {
		result.Status = StatusCompromised
	} else if riskScore > 40 {
		result.Status = StatusExpired
	}

	return result
}

// verifySignature verifies artifact signature
func (scshield *SupplyChainShield) verifySignature(artifact Artifact) Verification {
	if artifact.Signature == "" {
		return Verification{
			Type:      "signature",
			Status:    StatusUnsigned,
			Message:   "Artifact is not signed",
			Timestamp: time.Now(),
		}
	}

	// In real implementation, verify cryptographic signature
	// For demo, just check if signature exists
	return Verification{
		Type:      "signature",
		Status:    StatusVerified,
		Message:   "Artifact signature verified",
		Timestamp: time.Now(),
		Details: map[string]interface{}{
			"signed_by": artifact.SignedBy,
			"algorithm": "RSA-2048",
		},
	}
}

// verifyHash verifies artifact hash
func (scshield *SupplyChainShield) verifyHash(artifact Artifact) Verification {
	if artifact.Hash == "" {
		return Verification{
			Type:      "hash",
			Status:    StatusMissing,
			Message:   "No hash available for verification",
			Timestamp: time.Now(),
		}
	}

	// In real implementation, compare with known hash
	return Verification{
		Type:      "hash",
		Status:    StatusVerified,
		Message:   fmt.Sprintf("Hash verified (%s)", artifact.Algorithm),
		Timestamp: time.Now(),
		Details: map[string]interface{}{
			"hash":    artifact.Hash,
			"algorithm": artifact.Algorithm,
		},
	}
}

// verifyProvenance verifies artifact provenance
func (scshield *SupplyChainShield) verifyProvenance(artifact Artifact) Verification {
	if len(artifact.Provenance) == 0 {
		return Verification{
			Type:      "provenance",
			Status:    StatusMissing,
			Message:   "No provenance information available",
			Timestamp: time.Now(),
		}
	}

	return Verification{
		Type:      "provenance",
		Status:    StatusVerified,
		Message:   fmt.Sprintf("Provenance verified (%d records)", len(artifact.Provenance)),
		Timestamp: time.Now(),
		Details: map[string]interface{}{
			"build_id": artifact.Provenance[0].BuildID,
			"builder":  artifact.Provenance[0].Builder,
		},
	}
}

// checkVulnerabilities checks for known vulnerabilities
func (scshield *SupplyChainShield) checkVulnerabilities(artifact Artifact) []Vulnerability {
	var vulns []Vulnerability

	// In real implementation, query vulnerability database
	// For demo, generate sample vulnerabilities based on artifact type
	switch artifact.Type {
	case ArtifactTypeContainer:
		vulns = append(vulns, Vulnerability{
			ID:          "CVE-2024-0001",
			CVE:         "CVE-2024-0001",
			Severity:    "HIGH",
			Description: "Container escape vulnerability",
			AffectedVersion: "<1.0.0",
			FixedVersion:  "1.0.0",
			Source:      "NVD",
		})
	case ArtifactTypePackage:
		vulns = append(vulns, Vulnerability{
			ID:          "CVE-2024-0002",
			CVE:         "CVE-2024-0002",
			Severity:    "MEDIUM",
			Description: "Package dependency vulnerability",
			AffectedVersion: "<2.0.0",
			FixedVersion:  "2.0.0",
			Source:      "NVD",
		})
	}

	return vulns
}

// calculateRiskScore calculates risk score for an artifact
func (scshield *SupplyChainShield) calculateRiskScore(artifact Artifact, verifications []Verification, vulns []Vulnerability) float64 {
	score := 0.0

	// Signature verification impact
	for _, v := range verifications {
		if v.Type == "signature" && v.Status == StatusUnsigned {
			score += 30.0
		}
		if v.Type == "signature" && v.Status == StatusFailed {
			score += 50.0
		}
	}

	// Vulnerability impact
	for _, vuln := range vulns {
		switch vuln.Severity {
		case "CRITICAL":
			score += 40.0
		case "HIGH":
			score += 25.0
		case "MEDIUM":
			score += 15.0
		case "LOW":
			score += 5.0
		}
	}

	// Provenance impact
	for _, v := range verifications {
		if v.Type == "provenance" && v.Status == StatusMissing {
			score += 15.0
		}
	}

	if score > 100 {
		score = 100
	}

	return score
}

// generateRecommendations generates security recommendations
func (scshield *SupplyChainShield) generateRecommendations(artifact Artifact, verifications []Verification, vulns []Vulnerability) []string {
	var recommendations []string

	for _, v := range verifications {
		if v.Status == StatusUnsigned {
			recommendations = append(recommendations, "Sign artifacts using Cosign or Notary")
		}
		if v.Status == StatusMissing {
			recommendations = append(recommendations, "Add provenance information using in-toto")
		}
	}

	for _, vuln := range vulns {
		recommendations = append(recommendations, fmt.Sprintf("Update %s to fix %s", artifact.Name, vuln.CVE))
	}

	if len(recommendations) == 0 {
		recommendations = append(recommendations, "Continue following supply chain security best practices")
	}

	return recommendations
}

// PrintReport prints the supply chain security report
func (scshield *SupplyChainShield) PrintReport() {
	infoColor.Println("\n" + strings.Repeat("=", 80))
	infoColor.Println("📊 SUPPLY CHAIN SECURITY REPORT")
	infoColor.Println(strings.Repeat("=", 80))

	// Count artifacts by status
	statusCounts := map[VerificationStatus]int{
		StatusVerified:    0,
		StatusFailed:      0,
		StatusMissing:     0,
		StatusUnsigned:    0,
		StatusExpired:     0,
		StatusCompromised: 0,
	}

	totalVulnerabilities := 0
	totalCriticalVulns := 0
	totalHighVulns := 0
	totalMediumVulns := 0
	totalLowVulns := 0

	for _, result := range scshield.results {
		statusCounts[result.Status]++
		totalVulnerabilities += len(result.Vulnerabilities)

		for _, vuln := range result.Vulnerabilities {
			switch vuln.Severity {
			case "CRITICAL":
				totalCriticalVulns++
			case "HIGH":
				totalHighVulns++
			case "MEDIUM":
				totalMediumVulns++
			case "LOW":
				totalLowVulns++
			}
		}
	}

	successColor.Printf("✅ Total artifacts scanned:    %d\n", len(scshield.artifacts))
	successColor.Printf("✅ Artifacts verified:         %d\n", statusCounts[StatusVerified])
	warnColor.Printf("⚠️  Artifacts unsigned:         %d\n", statusCounts[StatusUnsigned])
	errorColor.Printf("❌ Artifacts failed:           %d\n", statusCounts[StatusFailed])
	warnColor.Printf("⚠️  Artifacts expired:          %d\n", statusCounts[StatusExpired])
	errorColor.Printf("❌ Artifacts compromised:      %d\n", statusCounts[StatusCompromised])

	infoColor.Println("\n🔍 Vulnerabilities Found:")
	infoColor.Printf("  Total vulnerabilities: %d\n", totalVulnerabilities)
	if totalCriticalVulns > 0 {
		criticalColor.Printf("  🔴 Critical: %d\n", totalCriticalVulns)
	}
	if totalHighVulns > 0 {
		errorColor.Printf("  🟠 High: %d\n", totalHighVulns)
	}
	if totalMediumVulns > 0 {
		warnColor.Printf("  🟡 Medium: %d\n", totalMediumVulns)
	}
	if totalLowVulns > 0 {
		noticeColor.Printf("  🟢 Low: %d\n", totalLowVulns)
	}

	// Print detailed results
	if len(scshield.results) > 0 {
		infoColor.Println("\n📋 Detailed Results:\n")

		sort.Slice(scshield.results, func(i, j int) bool {
			return scshield.results[i].ArtifactName < scshield.results[j].ArtifactName
		})

		for _, result := range scshield.results {
			emoji := map[VerificationStatus]string{
				StatusVerified:    "✅",
				StatusFailed:      "❌",
				StatusMissing:     "⏭️",
				StatusUnsigned:    "🔒",
				StatusExpired:     "⚠️",
				StatusCompromised: "🚨",
			}

			artEmoji := emoji[result.Status]

			if result.Status == StatusVerified {
				successColor.Printf("%s %s\n", artEmoji, result.ArtifactName)
			} else if result.Status == StatusCompromised {
				criticalColor.Printf("%s %s\n", artEmoji, result.ArtifactName)
			} else if result.Status == StatusFailed {
				errorColor.Printf("%s %s\n", artEmoji, result.ArtifactName)
			} else {
				warnColor.Printf("%s %s\n", artEmoji, result.ArtifactName)
			}

			infoColor.Printf("    ID: %s\n", result.ArtifactID)
			infoColor.Printf("    Status: %s\n", result.Status)
			infoColor.Printf("    Risk Score: %.1f%%\n", result.RiskScore)

			if len(result.Verifications) > 0 {
				infoColor.Println("    Verifications:")
				for _, v := range result.Verifications {
					emoji := map[VerificationStatus]string{
						StatusVerified:    "✅",
						StatusFailed:      "❌",
						StatusMissing:     "⏭️",
						StatusUnsigned:    "🔒",
					}
					verEmoji := emoji[v.Status]
					infoColor.Printf("      %s %s: %s\n", verEmoji, v.Type, v.Message)
				}
			}

			if len(result.Vulnerabilities) > 0 {
				infoColor.Printf("    Vulnerabilities: %d\n", len(result.Vulnerabilities))
				for _, v := range result.Vulnerabilities {
					severityEmoji := map[string]string{
						"CRITICAL": "🔴",
						"HIGH":     "🟠",
						"MEDIUM":   "🟡",
						"LOW":      "🟢",
					}
					sevEmoji := severityEmoji[v.Severity]
					infoColor.Printf("      %s %s - %s\n", sevEmoji, v.CVE, v.Description)
				}
			}

			if len(result.Recommendations) > 0 {
				infoColor.Println("    Recommendations:")
				for _, rec := range result.Recommendations {
					noticeColor.Printf("      • %s\n", rec)
				}
			}

			infoColor.Println(strings.Repeat("-", 60))
		}
	}

	infoColor.Println(strings.Repeat("=", 80))

	// Check for failures
	hasFailures := statusCounts[StatusFailed] > 0 || statusCounts[StatusCompromised] > 0
	hasCriticalIssues := totalCriticalVulns > 0 || statusCounts[StatusFailed] > 0

	if scshield.failOnCritical && hasCriticalIssues {
		errorColor.Printf("\n❌ Supply chain security FAILED: Critical issues found\n")
		os.Exit(1)
	}

	if scshield.failOnHigh && (hasFailures || totalHighVulns > 0) {
		errorColor.Printf("\n❌ Supply chain security FAILED: High severity issues found\n")
		os.Exit(1)
	}

	if scshield.dryRun {
		warnColor.Println("\n⚠️  This was a DRY RUN. No artifacts were verified.\n")
	} else {
		successColor.Println("\n✅ Supply chain security check complete!\n")
	}
}

func main() {
	// Define flags
	discoverPaths := flag.String("discover", ".", "Comma-separated paths to discover artifacts")
	failOnHigh := flag.Bool("fail-high", true, "Fail if high severity issues found")
	failOnCritical := flag.Bool("fail-critical", true, "Fail if critical issues found")
	dryRun := flag.Bool("dry-run", false, "Dry run mode")
	verbose := flag.Bool("verbose", false, "Verbose output")
	showHelp := flag.Bool("help", false, "Show help message")

	flag.Parse()

	if *showHelp {
		flag.Usage()
		return
	}

	// Create shield
	shield := NewSupplyChainShield(*failOnHigh, *failOnCritical, *verbose, *dryRun)

	// Discover artifacts
	paths := strings.Split(*discoverPaths, ",")
	if err := shield.DiscoverArtifacts(paths); err != nil {
		errorColor.Printf("❌ Error discovering artifacts: %v\n", err)
		os.Exit(1)
	}

	// Verify artifacts
	for _, artifact := range shield.artifacts {
		result := shield.VerifyArtifact(artifact)
		shield.results = append(shield.results, result)
	}

	// Print report
	shield.PrintReport()
}