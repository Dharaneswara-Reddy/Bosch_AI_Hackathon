# Problem Statement: Software Supply Chain Guardian (transcribed)

Source: `Problem_Statement/Amrita_BD Hackathon_Problem_Statement.pdf` (6 slides, Bosch BGSW/HRL-FHE, dated 2026-10-06).
The PDF has no text layer apart from the footer. Every slide is one image. This file copies each slide line by line.

---

## Slide 1: Title

- **Software Supply Chain Guardian**
- KNOW WHAT YOU BUILD. TRUST WHAT YOU SHIP.
- Ecosystem icons: Git, npm, Python, Docker, Java
- Themes along the bottom: Secure Dependencies · Detect Risks · Enable Developers · Improve Resilience · Stronger Together

---

## Slide 2: Problem and expected flow

**Software Supply Chain Guardian**: KNOW WHAT YOU BUILD. TRUST WHAT YOU SHIP.

### Problem Statement
Build an Agentic AI Solution that continuously analyzes the software supply chain to **identify dependency risks, vulnerabilities, and suspicious changes** before they impact applications.

### Explanation in Detail
- Modern applications are assembled from open-source libraries, transitive dependencies, container images, build tools, and third-party components that **continuously change**.
- Traditional security tools can find known vulnerabilities, but teams still need to understand which risks actually matter, whether they are reachable or exploitable, what changed in the supply chain, and how to remediate issues safely.
- Build an AI-powered guardian that **connects evidence from the software supply chain with application context**, prioritizes meaningful risks, and recommends safe actions.

### What a Team's Solution Should Do
1. **Discover the Software Supply Chain:** Identify direct and transitive dependencies, container components, package versions, and their relationships. Generate or consume an SBOM and build a dependency view.
2. **Detect Risks & Suspicious Changes:** Identify known vulnerabilities as well as suspicious changes such as typosquatted packages, unexpected dependencies, unsafe install scripts, untrusted images, or integrity changes.
3. **Analyze & Prioritize with AI:** Correlate severity with exploitability, reachability, exposure, provenance, and application context to determine which findings actually require attention.
4. **Recommend Safe Remediation:** Recommend the most appropriate action, such as upgrade, replace, pin, remove, mitigate, block, or request further review, with supporting evidence.
5. **Validate & Report:** Build and test proposed changes, rescan the resulting application, verify that the risk has been reduced, detect newly introduced problems, and provide a clear evidence-based report.

Flow: Discover → Detect → Analyze → Remediate → Validate

---

## Slide 3: Important Guidelines

*Build Responsibly. Experiment Safely. Create Impact.*

### Examples of Supply Chain Risks Teams May Analyze
- Vulnerable direct dependency
- Vulnerable transitive dependency
- Typosquatted or malicious package
- Suspicious package update or install script
- Untrusted container image or artifact
- Unexpected lockfile or dependency change
- Unpinned or unsafe CI/CD component

### Sample Application Guidelines
- Use a free, open-source application from a public repository.
- The application should contain a realistic dependency tree with direct and transitive dependencies.
- The application should be containerized and runnable within the team's own local or sandbox environment.
- Teams should be able to build, test and scan the application locally.
- Teams should document the repository, setup steps, dependencies and tools used in their submission.

### Out of Scope
- Scanning or attacking real production systems.
- Accessing repositories, registries or infrastructure outside the team's authorized sandbox.
- Publishing malicious or modified packages to public package registries.
- Exposing or using real credentials, secrets or access tokens.
- Automatically merging, deploying or releasing remediation changes without human approval.
- Any activity that impacts other teams, participants or shared infrastructure.

---

## Slide 4: Day 1: Build the Guardian's Eyes

*Discover the software supply chain, detect risks, and explain what it found with evidence.*

1. **Discover Components**
   - Analyze package manifests and lockfiles (example files shown: `package.json`, `pom.xml`)
   - Identify direct and transitive dependencies
   - Capture component names and versions
2. **Build the Supply Chain View**
   - Generate or consume an SBOM (CycloneDX or SPDX)
   - Build the dependency graph
   - Identify where each component originates
   - Inspect at least one container image or CI/CD workflow
3. **Detect Vulnerabilities** (example card: CVE-2024-1234, CVSS 9.8, Fix available)
   - Correlate components with known vulnerabilities
   - Capture CVE, severity and available fixes
   - Trace vulnerable transitive dependencies back to their source
4. **Detect Suspicious Changes** (example tags: Typosquatting, Unexpected dependency, Suspicious update, Unsafe install script, Untrusted image, Modified lockfile)
   - Identify at least one supply-chain anomaly, for example: Unexpected dependency · Typosquatted package · Suspicious package update · Unsafe install script · Untrusted image · Modified lockfile
5. **Present Evidence** (card fields: Component, Dependency path, Evidence, Risk level)
   - Show what was detected
   - Which component is affected
   - Dependency path
   - Supporting evidence
   - Initial risk level

- **Day 1 Checkpoint:** "Show us what is in the application, what changed, and what appears risky."
- **Expected Outcome (Day 1):** Repository → SBOM → Dependency Graph → Risk Detection → Evidence
- **Key Takeaway:** Day 1 is about visibility and detection. Remediation comes on Day 2.
- Status panel in the image: SBOM Generated ✓, Dependencies Mapped ✓, Risks Identified ✓

---

## Slide 5: Day 2: Build the Guardian's Brain & Shield

*Prioritize the most relevant risks, recommend safe remediation, and verify that the proposed change protects the application without introducing new problems.*

1. **Prioritize Risks:** Focus on what truly matters (Critical / High / Medium / Low)
   - Combine severity with exploitability, reachability and exposure
   - Consider whether the dependency is used in production
   - Distinguish urgent risks from lower-priority findings
   - Provide an explainable risk score and confidence level
2. **Investigate Suspicious Changes:** Look beyond known CVEs
   - Analyze at least one non-CVE supply-chain risk
   - Compare package versions, manifests or lockfiles
   - Identify suspicious scripts, provenance gaps or integrity changes
   - Clearly separate verified evidence from AI-generated inference
3. **Recommend Safe Remediation:** Suggest the right action
   - Upgrade to a safe version
   - Replace or remove the dependency
   - Pin a trusted version
   - Update the container base image
   - Block the unsafe component
   - Escalate for security review
   - Include expected risk reduction, compatibility impact and rollback option
4. **Validate the Proposed Fix:** Test before you trust (Build ✓, Run Tests ✓, Rescan ✓; Before / After)
   - Apply the remediation in a controlled branch or sandbox
   - Build the application
   - Run unit and integration tests
   - Rescan the resulting artifact
   - Compare before-and-after SBOM
   - Detect newly introduced vulnerabilities or dependencies
5. **Verify & Report:** Show the complete story
   - Original finding and supporting evidence
   - Recommended and approved action
   - Build and test results
   - Before-and-after risk status
   - Remaining or accepted risk
   - Final confidence and audit trail

- **Day 2 Final Demonstration:** "Show us how the Guardian takes a finding from detection to verified remediation."
- **Expected Outcome (Day 2):** Prioritized Risk → Recommended Fix → **Human Approval** → Build & Test → Rescan → Verified Remediation
- **Key Takeaway:** Day 2 is about contextual reasoning, safe action and verified protection.
- Image labels: Analyze/Reason → Recommend/Fix → Validate/Test → Protect/Verify → Secure Release; inputs: CVE, Suspicious Change, Policy Violation.

---

## Slide 6: Stretch Goals & Deliverables

*Go beyond the basics. Build a more intelligent, capable and impactful guardian.*

### Stretch Goals: Take it further. Make a bigger impact.
1. **Reachability Analysis:** Determine whether vulnerable code is actually used by the application and adjust the risk priority accordingly.
2. **Automated Remediation:** Generate a dependency update or pull request with the proposed fix, rationale, validation results and rollback guidance.
3. **Provenance Verification:** Validate artifact signatures, attestations and build provenance using Cosign, Sigstore, in-toto or SLSA.
4. **Advanced Package Risk Detection:** Detect dependency confusion, maintainer changes, unusual release activity and suspicious package behavior.
5. **Policy-as-Code:** Use Open Policy Agent, Conftest or equivalent controls to block unsafe components or builds.
6. **Continuous Monitoring:** Monitor the software inventory for newly disclosed vulnerabilities and automatically reassess application risk.

### Expected Deliverables: Show. Explain. Enable. Inspire.
- **Working Prototype:** A functional solution demonstrating the complete Guardian workflow.
- **Architecture Overview:** A diagram showing agents, tools, data sources, AI interactions, approval points and evidence storage.
- **Source Code & Setup:** Source code, configuration, setup instructions, sample policies, prompts and known limitations.
- **Live Demonstration:** An end-to-end scenario covering discovery, detection, prioritization, remediation, approval and validation.
- **Guardian Report:** A human-readable and machine-readable report containing:
  - Component inventory and dependency paths
  - Findings and supporting evidence
  - Risk ranking and recommended actions
  - Validation results
  - Remaining or accepted risks
- **Responsible AI & Security Note:** Explain where AI is used, how hallucinations are controlled, which actions require human approval and how source code, credentials and secrets are protected.

**Key Message:** Core capabilities demonstrate completeness. Stretch goals demonstrate innovation.
