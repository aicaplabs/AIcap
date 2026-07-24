// SPDX 2.3 SBOM export (Wave 22).
//
// AIcap already emitted CycloneDX. SPDX is the other half of the SBOM
// world — the Linux Foundation format, standardised as ISO/IEC 5962, and
// the one named in US federal procurement guidance and in a good share of
// enterprise vendor questionnaires. The two formats are not
// interchangeable and neither subsumes the other: a questionnaire asking
// for "an SPDX SBOM" is not satisfied by a CycloneDX file, however
// complete it is. Supporting only one dialect means losing deals over a
// serialisation format rather than over the product.
//
// Targeting 2.3 rather than 3.0 is a deliberate trade. SPDX 3.0 added an
// AI profile that models exactly what this product produces — model
// metadata, energy consumption, safety-risk assessment — and is
// genuinely the better fit on paper. But it is a JSON-LD element graph
// that comparatively little tooling ingests today, and the entire point
// of emitting SPDX is to be consumed by somebody else's scanner. So this
// targets the version that gets parsed, and carries the AI-specific data
// in annotations and external references. Revisit when 3.0 ingestion is
// common.
//
// Correctness notes that cost real care:
//
//   - SPDXIDs must match SPDXRef-[a-zA-Z0-9.-]+. Package names in this
//     BOM include "@anthropic-ai/sdk", "Hardcoded Model", and file paths,
//     none of which are legal. They are sanitised, and collisions after
//     sanitisation are disambiguated rather than silently merged.
//   - Licence fields must be SPDX expressions. "Proprietary (OpenAI)" is
//     not one. Emitting it would produce a document that fails
//     validation, so unrecognised licences become LicenseRef entries with
//     the original text preserved in hasExtractedLicensingInfos.
//   - Every package needs downloadLocation; NOASSERTION is the correct
//     value for "we did not determine it", and is honest here.

package compliance

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"

	"aicap/pkg/types"
)

// spdxToolVersion identifies the producing tool in creationInfo.
const spdxToolVersion = "AIcap"

// knownSPDXLicenses is the small set of identifiers this scanner can
// actually produce and vouch for — Hugging Face returns lower-cased SPDX
// ids, and the model-family catalog emits vendor prose. Anything not in
// here becomes a LicenseRef rather than being passed off as a valid
// expression.
var knownSPDXLicenses = map[string]string{
	"mit":          "MIT",
	"apache-2.0":   "Apache-2.0",
	"apache2.0":    "Apache-2.0",
	"bsd-3-clause": "BSD-3-Clause",
	"bsd-2-clause": "BSD-2-Clause",
	"gpl-3.0":      "GPL-3.0-only",
	"agpl-3.0":     "AGPL-3.0-only",
	"lgpl-3.0":     "LGPL-3.0-only",
	"mpl-2.0":      "MPL-2.0",
	"cc-by-4.0":    "CC-BY-4.0",
	"cc-by-sa-4.0": "CC-BY-SA-4.0",
	"cc0-1.0":      "CC0-1.0",
	"unlicense":    "Unlicense",
	"isc":          "ISC",
}

var spdxIDUnsafe = regexp.MustCompile(`[^a-zA-Z0-9.\-]+`)

// GenerateSPDXDocument renders the AI-BOM as an SPDX 2.3 document.
//
// The register is used to attach advisory references. SPDX 2.3 has no
// native vulnerability model — that is a genuine gap in the format and
// the reason CycloneDX carries the richer vulnerability data here — so
// advisories are attached as SECURITY external references, which is the
// established convention.
func GenerateSPDXDocument(bom types.AIBOM, register types.RiskRegister) types.SPDXDocument {
	now := time.Now().UTC().Format("2006-01-02T15:04:05Z")

	projectName := bom.ProjectName
	if projectName == "" {
		projectName = "ai-bom"
	}
	rootID := "SPDXRef-Package-root"

	// Advisory URLs per component, so a package can carry its own.
	advisoriesByComponent := map[string][]string{}
	for _, f := range register.Findings {
		key := strings.ToLower(f.Component)
		for _, v := range f.LiveVulns {
			if v.ID != "" {
				advisoriesByComponent[key] = append(advisoriesByComponent[key],
					"https://osv.dev/vulnerability/"+v.ID)
			}
		}
	}

	packages := []types.SPDXPackage{{
		SPDXID:           rootID,
		Name:             projectName,
		VersionInfo:      bom.CommitSha,
		DownloadLocation: "NOASSERTION",
		FilesAnalyzed:    false,
		LicenseConcluded: "NOASSERTION",
		LicenseDeclared:  "NOASSERTION",
		CopyrightText:    "NOASSERTION",
		PrimaryPurpose:   "APPLICATION",
		Comment:          "Root of the scanned project. Only AI components are enumerated — this is an AI-BOM, not a complete SBOM of the project's dependencies.",
	}}

	relationships := []types.SPDXRelationship{{
		SPDXElementID:      "SPDXRef-DOCUMENT",
		RelatedSPDXElement: rootID,
		RelationshipType:   "DESCRIBES",
	}}

	extracted := map[string]types.SPDXExtractedLicense{}
	usedIDs := map[string]bool{rootID: true}

	for _, dep := range bom.Dependencies {
		id := uniqueSPDXID("SPDXRef-Package-"+sanitiseSPDXID(dep.Name), usedIDs)
		usedIDs[id] = true

		declared, ext := spdxLicense(dep.License)
		if ext != nil {
			extracted[ext.LicenseID] = *ext
		}

		pkg := types.SPDXPackage{
			SPDXID:           id,
			Name:             dep.Name,
			VersionInfo:      spdxVersion(dep.Version),
			DownloadLocation: "NOASSERTION",
			FilesAnalyzed:    false,
			// Concluded stays NOASSERTION even when a licence is
			// declared: AIcap reads what the registry or the catalog
			// says, it does not perform the legal review that a
			// *concluded* licence asserts.
			LicenseConcluded: "NOASSERTION",
			LicenseDeclared:  declared,
			CopyrightText:    "NOASSERTION",
			PrimaryPurpose:   spdxPurpose(dep),
		}
		if dep.License != "" && declared == "NOASSERTION" {
			pkg.LicenseComments = "Reported by AIcap as: " + dep.License
		}

		if purl := GeneratePURL(dep); purl != "" {
			pkg.ExternalRefs = append(pkg.ExternalRefs, types.SPDXExternalRef{
				Category: "PACKAGE-MANAGER",
				Type:     "purl",
				Locator:  purl,
			})
		}
		for _, url := range advisoriesByComponent[strings.ToLower(dep.Name)] {
			pkg.ExternalRefs = append(pkg.ExternalRefs, types.SPDXExternalRef{
				Category: "SECURITY",
				Type:     "advisory",
				Locator:  url,
				Comment:  "Live OSV.dev advisory at scan time.",
			})
		}

		// SPDX 2.3 has no field for "why this component matters to an AI
		// risk assessment", so the scanner's own classification travels
		// as an annotation. This is the data SPDX 3.0's AI profile would
		// carry natively.
		note := "AIcap risk level: " + dep.RiskLevel + ". Ecosystem: " + dep.Ecosystem + "."
		if dep.Location != "" {
			note += " Detected at: " + dep.Location + "."
		}
		pkg.Annotations = append(pkg.Annotations, types.SPDXAnnotation{
			Annotator:         "Tool: " + spdxToolVersion,
			AnnotationDate:    now,
			AnnotationType:    "OTHER",
			AnnotationComment: note,
		})

		packages = append(packages, pkg)
		relationships = append(relationships, types.SPDXRelationship{
			SPDXElementID:      rootID,
			RelatedSPDXElement: id,
			RelationshipType:   "DEPENDS_ON",
		})
	}

	var extractedList []types.SPDXExtractedLicense
	for _, e := range extracted {
		extractedList = append(extractedList, e)
	}
	sort.Slice(extractedList, func(i, j int) bool {
		return extractedList[i].LicenseID < extractedList[j].LicenseID
	})

	return types.SPDXDocument{
		SPDXVersion: "SPDX-2.3",
		DataLicense: "CC0-1.0",
		SPDXID:      "SPDXRef-DOCUMENT",
		Name:        projectName,
		// Namespaces must be unique per document. Derived from project +
		// commit so the same scan is reproducible rather than minting a
		// fresh random namespace on every run.
		//
		// The hash is truncated, not the assembled string: slicing the
		// whole URI to a fixed width panics whenever the project name is
		// short enough to leave it under that width, which is most
		// projects.
		DocumentNamespace: "https://aicap.dev/spdx/" + sanitiseSPDXID(projectName) + "-" +
			hex.EncodeToString(namespaceDigest(projectName, bom.CommitSha)),
		CreationInfo: types.SPDXCreationInfo{
			Created:  now,
			Creators: []string{"Tool: " + spdxToolVersion, "Organization: AIcap"},
			Comment: "AI Bill of Materials generated by AIcap. Enumerates AI/ML components only " +
				"— models, frameworks, hosted model APIs, and model weight files — not the " +
				"project's complete dependency tree. Licence fields reflect what registries " +
				"and catalogs report; licenseConcluded is NOASSERTION throughout because no " +
				"legal review was performed.",
		},
		Packages:          packages,
		Relationships:     relationships,
		ExtractedLicenses: extractedList,
	}
}

// namespaceDigest returns the 16-byte prefix of the scan digest used to
// make a document namespace unique. Truncating here rather than on the
// finished URI keeps the result well-defined for any project name.
func namespaceDigest(projectName, commitSha string) []byte {
	sum := sha256.Sum256([]byte(projectName + "@" + commitSha))
	return sum[:16]
}

// sanitiseSPDXID makes a name safe for an SPDXID, which the spec limits
// to letters, digits, "." and "-".
func sanitiseSPDXID(name string) string {
	s := spdxIDUnsafe.ReplaceAllString(name, "-")
	s = strings.Trim(s, "-")
	if s == "" {
		s = "unnamed"
	}
	return s
}

// uniqueSPDXID disambiguates identifiers that collide after sanitisation.
// "@scope/pkg" and "scope-pkg" both sanitise to the same string, and two
// packages sharing an SPDXID would make the document invalid — and worse,
// would silently merge two components in the consumer's view.
func uniqueSPDXID(base string, used map[string]bool) string {
	if !used[base] {
		return base
	}
	for i := 2; ; i++ {
		candidate := fmt.Sprintf("%s-%d", base, i)
		if !used[candidate] {
			return candidate
		}
	}
}

// spdxVersion drops the scanner's placeholder versions. SPDX
// versionInfo is meant to be a version; "imported" is not one, and
// omitting the field is more honest than filling it with a marker only
// this tool understands.
func spdxVersion(v string) string {
	switch strings.ToLower(v) {
	case "", "unknown", "imported", "local", "docker-image", "docker-install", "docker-layer", "hidden":
		return ""
	}
	return v
}

// spdxPurpose maps a finding to an SPDX primaryPackagePurpose.
//
// SPDX 2.3's enumeration has no value for a machine-learning model —
// that arrived with 3.0's AI profile. Weight files therefore land on
// FILE, with the annotation carrying what they actually are.
func spdxPurpose(dep types.AIDependency) string {
	switch {
	case strings.HasPrefix(dep.Ecosystem, "Model Weight"):
		return "FILE"
	case strings.HasPrefix(dep.Ecosystem, "Container Image"):
		return "CONTAINER"
	case dep.Name == "Exposed Secret":
		return "OTHER"
	case dep.Name == "Hardcoded Model":
		return "OTHER"
	default:
		return "LIBRARY"
	}
}

// spdxLicence maps a reported licence onto a valid SPDX expression,
// returning an extracted-licence record when the value is not a
// recognised identifier.
func spdxLicense(raw string) (string, *types.SPDXExtractedLicense) {
	if strings.TrimSpace(raw) == "" {
		return "NOASSERTION", nil
	}
	if id, ok := knownSPDXLicenses[strings.ToLower(strings.TrimSpace(raw))]; ok {
		return id, nil
	}
	// Not a recognised identifier — most often vendor prose such as
	// "Proprietary (OpenAI)". A LicenseRef keeps the document valid and
	// preserves the original text rather than discarding it or passing
	// off prose as an SPDX expression.
	ref := "LicenseRef-AIcap-" + sanitiseSPDXID(raw)
	return ref, &types.SPDXExtractedLicense{
		LicenseID:     ref,
		ExtractedText: raw,
		Name:          raw,
		Comment:       "Not a recognised SPDX licence identifier. Reported verbatim by AIcap from a model registry or the model-family catalog; no legal review performed.",
	}
}
