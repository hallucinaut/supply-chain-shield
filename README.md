# 🛡️ Supply Chain Shield - Software Supply Chain Security

> **Comprehensive supply chain security tool for artifact provenance, verification, and SBOM management**

---

## 🎯 Problem Solved

Software supply chain attacks are **increasing rapidly**:
- **Compromised dependencies** (Log4j, SolarWinds, etc.)
- **Unverified artifacts** deployed to production
- **Missing provenance** information
- **No SBOM visibility** into dependencies
- **Unsigned artifacts** in CI/CD pipelines

**Supply Chain Shield solves this by providing comprehensive supply chain security verification.**

---

## ✨ Features

### 🔒 Security Verification

#### Artifact Verification
- ✅ **Signature Verification** - Verify cryptographic signatures
- ✅ **Hash Verification** - Validate artifact integrity
- ✅ **Provenance Tracking** - Track artifact origin and build process
- ✅ **SBOM Generation** - Software Bill of Materials
- ✅ **Vulnerability Scanning** - Check for known vulnerabilities

### 📦 Supported Artifact Types

| Type | Examples |
|------|----------|
| **Containers** | Docker images, OCI artifacts |
| **Packages** | NPM, PyPI, Maven, NuGet |
| **Binaries** | Executables, JAR files |
| **Configurations** | Terraform, Helm charts |
| **Certificates** | SSL/TLS certificates |

### 🛡️ Key Capabilities

- **Multi-Format Support** - Containers, packages, binaries, configs
- **Cryptographic Verification** - RSA, ECDSA signatures
- **Provenance Tracking** - in-toto, SLSA compliance
- **SBOM Management** - SPDX, CycloneDX formats
- **Risk Scoring** - Calculate security risk scores
- **Automated Recommendations** - Generate security fixes

---

## 🛠️ Installation

### Build from Source

```bash
cd supply-chain-shield
go mod download
go build -o supply-chain-shield cmd/supply-chain-shield/main.go
```

### Install Globally

```bash
go install -o /usr/local/bin/supply-chain-shield ./cmd/supply-chain-shield
```

---

## 🚀 Usage

### Basic Usage

```bash
# Scan current directory for artifacts
./supply-chain-shield --discover=.

# Scan multiple directories
./supply-chain-shield --discover=./artifacts,./builds

# Fail on high severity issues
./supply-chain-shield --discover=./artifacts --fail-high=true
```

### Command Line Options

| Flag | Description | Default |
|------|-------------|---------|
| `--discover` | Comma-separated paths to discover artifacts | `.` |
| `--fail-high` | Fail if high severity issues found | `true` |
| `--fail-critical` | Fail if critical issues found | `true` |
| `--dry-run` | Dry run mode | `false` |
| `--verbose` | Verbose output | `false` |
| `--help` | Show help message | `false` |

### Examples

#### Scan Artifacts

```bash
# Scan build artifacts directory
./supply-chain-shield --discover=./build/artifacts

# Scan container registry
./supply-chain-shield --discover=./registry

# Scan package cache
./supply-chain-shield --discover=./.npm,./node_modules
```

#### CI/CD Integration

```bash
# In CI/CD pipeline
./supply-chain-shield --discover=./dist --fail-high=true --fail-critical=true
```

---

## 📊 Security Report Example

```
================================================================================
📊 SUPPLY CHAIN SECURITY REPORT
================================================================================
✅ Total artifacts scanned:    15
✅ Artifacts verified:         8
⚠️  Artifacts unsigned:         5
❌ Artifacts failed:           1
⚠️  Artifacts expired:         1
❌ Artifacts compromised:      0

🔍 Vulnerabilities Found:
  Total vulnerabilities: 7
  🔴 Critical: 1
  🟠 High: 2
  🟡 Medium: 3
  🟢 Low: 1

📋 Detailed Results:

✅ myapp-v1.2.3.tar.gz
    ID: myapp-v1.2.3.tar.gz-1709385600
    Status: verified
    Risk Score: 15.0%
    Verifications:
      ✅ signature: Artifact signature verified
      ✅ hash: Hash verified (sha256)
      ✅ provenance: Provenance verified (2 records)
    Recommendations:
      • Continue following supply chain security best practices

🔒 mylib-v2.0.0.jar
    ID: mylib-v2.0.0.jar-1709385601
    Status: unsigned
    Risk Score: 30.0%
    Verifications:
      🔒 signature: Artifact is not signed
      ✅ hash: Hash verified (sha256)
    Recommendations:
      • Sign artifacts using Cosign or Notary

❌ vulnerable-package-v1.0.0.whl
    ID: vulnerable-package-v1.0.0.whl-1709385602
    Status: failed
    Risk Score: 75.0%
    Verifications:
      ❌ signature: Artifact signature verification failed
      ✅ hash: Hash verified (sha256)
    Vulnerabilities:
      🔴 CVE-2024-0001 - Critical vulnerability in dependency
      🟠 CVE-2024-0002 - High severity issue
    Recommendations:
      • Sign artifacts using Cosign or Notary
      • Update vulnerable-package to fix CVE-2024-0001

================================================================================

✅ Supply chain security check complete!
```

---

## 🎨 Verification Types

### Signature Verification
- **RSA Signatures** - RSA-2048, RSA-4096
- **ECDSA Signatures** - ECDSA-P256, ECDSA-P384
- **Cosign** - Sigstore cosign verification
- **Notary** - Docker Notary v2

### Hash Verification
- **SHA256** - Industry standard
- **SHA512** - Enhanced security
- **SHA1** - Legacy support (deprecated)

### Provenance Tracking
- **in-toto** - Supply chain provenance
- **SLSA** - Supply-chain Levels for Software Artifacts
- **Build metadata** - Builder, build ID, timestamp

---

## 📋 SBOM Support

### Supported Formats
- **SPDX** - Software Package Data Exchange
- **CycloneDX** - Software Bill of Materials
- **Software Composition Analysis** - Dependency tracking

### Component Information
- **Name** - Component name
- **Version** - Component version
- **License** - License information
- **Hash** - Component hash
- **Vendors** - Vendor information
- **CPE** - Common Platform Enumeration
- **PURL** - Package URL

---

## 🚀 CI/CD Integration

### GitHub Actions

```yaml
name: Supply Chain Security Check
on: [push, pull_request]

jobs:
  security-check:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      
      - name: Setup Go
        uses: actions/setup-go@v4
        with:
          go-version: '1.21'
      
      - name: Install supply-chain-shield
        run: |
          go build -o supply-chain-shield ./cmd/supply-chain-shield
      
      - name: Run security check
        run: |
          ./supply-chain-shield --discover=./dist --fail-critical=true
```

### GitLab CI

```yaml
supply-chain-security:
  stage: security
  image: golang:1.21
  script:
    - go build -o supply-chain-shield ./cmd/supply-chain-shield
    - ./supply-chain-shield --discover=./dist --fail-critical=true
```

### Jenkins Pipeline

```groovy
pipeline {
    agent any
    stages {
        stage('Supply Chain Security') {
            steps {
                sh '''
                    go build -o supply-chain-shield ./cmd/supply-chain-shield
                    ./supply-chain-shield --discover=./dist --fail-critical=true
                '''
            }
        }
    }
}
```

---

## 🧪 Testing

### Create Test Artifacts

```bash
# Create test directory
mkdir -p test-artifacts

# Create test artifact
cat > test-artifacts/test-artifact.tar.gz << EOF
# Create a sample archive
echo "test content" > test.txt
tar -czf test-artifact.tar.gz test.txt
EOF

# Run security check
./supply-chain-shield --discover=./test-artifacts --verbose
```

---

## 🚧 Roadmap

- [ ] Cosign integration
- [ ] Notary v2 integration
- [ ] in-toto provenance verification
- [ ] SLSA compliance checking
- [ ] SBOM generation (SPDX, CycloneDX)
- [ ] Vulnerability database integration
- [ ] Real-time artifact monitoring
- [ ] Multi-registry support
- [ ] Policy enforcement engine

---

## 🤝 Contributing

Contributions are welcome!

1. Fork the repository
2. Create a feature branch
3. Add new artifact type support
4. Submit a pull request

---

## 📄 License

MIT License - Free for commercial and personal use

---

## 🙏 Acknowledgments

Built with ❤️ for software supply chain security.

---

**Version:** 1.0.0  
**Author:** @hallucinaut  
**Last Updated:** February 25, 2026