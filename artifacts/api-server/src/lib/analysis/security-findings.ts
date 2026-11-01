/**
 * Static security-finding engine.
 *
 * Replaces a whole class of bug in the previous implementation: findings were
 * detected by concatenating every file's strings into one blob and running a
 * single regex pass per category. That meant at most one finding per
 * category regardless of how many files actually had a problem, and it
 * treated the mere presence of a word (`wget`, `curl`, `nc`) as a malware
 * indicator — OpenWrt legitimately ships all three.
 *
 * This engine instead walks files individually, so every offending file gets
 * its own finding with its own evidence, and distinguishes "a utility is
 * present" from "a utility is used in a way that warrants review" (piped to a
 * shell, fetching then executing, referenced from a startup script).
 *
 * Every finding is evidence-backed: the path and the exact (masked, where
 * sensitive) match are recorded. Nothing here reports a CVE — that requires a
 * CVE database this deployment does not have, and is left null rather than
 * guessed.
 */

import { readFile } from "node:fs/promises";
import { join } from "node:path";
import type { AnalyzedFile } from "./static-analysis";

export type FindingCategory =
  | "Hardcoded Credentials"
  | "Insecure Configuration"
  | "Outdated/Vulnerable Software"
  | "Weak Cryptography"
  | "Insecure Network Services"
  | "Excessive/Unsafe File Permissions"
  | "Sensitive Information Exposure"
  | "Dangerous Commands/Code Execution Indicators"
  | "Other Security Weaknesses";

export interface SecurityFinding {
  category: FindingCategory;
  title: string;
  severity: "Critical" | "High" | "Medium" | "Low" | "Informational";
  affectedPath: string;
  description: string;
  evidence: string;
  confidence: "high" | "medium" | "low";
  recommendation: string;
  cve: string | null;
  /** Component this finding is about, when applicable (feeds a future CVE match). */
  component: string | null;
  componentVersion: string | null;
  /** How the finding was derived, for an analyst auditing the result. */
  detectionSource: string;
  /**
   * True for findings that represent a malware/backdoor-style indicator
   * specifically. Used to report a malware-indicator count without double
   * counting every finding as risk twice.
   */
  isMalwareIndicator: boolean;
}

const MAX_CONTENT_BYTES = 512 * 1024;

function mask(value: string): string {
  const trimmed = value.trim().replace(/^["']|["']$/g, "");
  if (trimmed.length <= 3) return "***";
  return `${trimmed.slice(0, 2)}${"*".repeat(Math.min(18, Math.max(4, trimmed.length - 2)))}`;
}

/** Read up to a bounded amount of a file's content as text, or "" on any failure. */
async function readTextSample(root: string, file: AnalyzedFile): Promise<string> {
  if (file.sizeBytes === 0 || file.type.startsWith("symlink") || file.sizeBytes > 8 * 1024 * 1024) return "";
  try {
    const buffer = await readFile(join(root, file.sandboxPath));
    return buffer.subarray(0, MAX_CONTENT_BYTES).toString("latin1");
  } catch {
    return "";
  }
}

// ---------------------------------------------------------------------------
// Credential detection — typed, not a single catch-all regex
// ---------------------------------------------------------------------------

interface CredentialRule {
  type: string;
  pattern: RegExp;
  severity: SecurityFinding["severity"];
  confidence: SecurityFinding["confidence"];
  recommendation: string;
}

const CREDENTIAL_RULES: readonly CredentialRule[] = Object.freeze([
  {
    type: "AWS access key",
    pattern: /\bAKIA[0-9A-Z]{16}\b/,
    severity: "Critical",
    confidence: "high",
    recommendation: "Revoke this AWS key immediately in IAM, rotate it, and remove it from firmware.",
  },
  {
    type: "Google API key",
    pattern: /\bAIza[0-9A-Za-z_-]{35}\b/,
    severity: "Critical",
    confidence: "high",
    recommendation: "Revoke this Google API key and restrict/rotate it; remove it from firmware.",
  },
  {
    type: "Slack token",
    pattern: /\bxox[baprs]-[0-9A-Za-z-]{10,}\b/,
    severity: "Critical",
    confidence: "high",
    recommendation: "Revoke this Slack token and remove it from firmware.",
  },
  {
    type: "JWT",
    pattern: /\beyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\b/,
    severity: "High",
    confidence: "medium",
    recommendation: "Confirm whether this is a long-lived credential; if so, revoke and remove it from firmware.",
  },
  {
    type: "Bearer token",
    pattern: /\bBearer\s+[A-Za-z0-9_-]{16,}\b/,
    severity: "High",
    confidence: "medium",
    recommendation: "Remove the hardcoded bearer token and issue tokens per-device at provisioning time.",
  },
  {
    type: "Database connection string",
    pattern: /\b(?:mysql|postgres(?:ql)?|mongodb):\/\/[^:\s]+:[^@\s]+@[^\s"']+/i,
    severity: "Critical",
    confidence: "high",
    recommendation: "Remove the embedded database credential; rotate it and use a runtime secret store.",
  },
  {
    type: "Generic API key/token",
    pattern: /\b(?:api[_-]?key|access[_-]?token|auth[_-]?token|secret[_-]?key)\s*[=:]\s*["']?[A-Za-z0-9_\-./+]{8,}/i,
    severity: "High",
    confidence: "medium",
    recommendation: "Revoke and rotate the token, remove it from firmware, and provision secrets at runtime.",
  },
  {
    type: "Password",
    pattern: /\b(?:password|passwd|pwd)\s*[=:]\s*["']?[^\s"'#]{3,}/i,
    severity: "High",
    confidence: "medium",
    recommendation: "Remove the static password, rotate it, and require the user to set a device-specific password at first boot.",
  },
  {
    type: "Private key",
    pattern: /-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----/,
    severity: "Critical",
    confidence: "high",
    recommendation: "Remove the private key from firmware, rotate it, and provision device-unique keys at manufacturing or first boot.",
  },
]);

/** Well-known default-credential pairs that appear verbatim in firmware config. */
const DEFAULT_CREDENTIAL_PAIRS = Object.freeze([
  /\badmin[:\s]+admin\b/i,
  /\broot[:\s]+root\b/i,
  /\badmin[:\s]+password\b/i,
  /\bdefault[:\s]+password\b/i,
  /\buser(?:name)?[=:]\s*admin\b.{0,80}\bpass(?:word)?[=:]\s*admin\b/is,
]);

function detectCredentials(file: AnalyzedFile, content: string): SecurityFinding[] {
  const findings: SecurityFinding[] = [];

  for (const rule of CREDENTIAL_RULES) {
    const match = rule.pattern.exec(content);
    if (!match) continue;
    const isKeyMaterial = rule.type === "Private key";
    findings.push({
      category: rule.type === "Private key" ? "Sensitive Information Exposure" : "Hardcoded Credentials",
      title: `${rule.type} found in extracted content`,
      severity: rule.severity,
      affectedPath: file.path,
      description: isKeyMaterial
        ? "PEM private-key material was found in this file."
        : `A ${rule.type.toLowerCase()} pattern was matched in this file. The value is masked below.`,
      evidence: isKeyMaterial ? "-----BEGIN PRIVATE KEY----- (value withheld)" : mask(match[0]).slice(0, 160),
      confidence: rule.confidence,
      recommendation: rule.recommendation,
      cve: null,
      component: null,
      componentVersion: null,
      detectionSource: `pattern match: ${rule.type}`,
      isMalwareIndicator: false,
    });
  }

  for (const pattern of DEFAULT_CREDENTIAL_PAIRS) {
    const match = pattern.exec(content);
    if (!match) continue;
    findings.push({
      category: "Hardcoded Credentials",
      title: "Default credential pair found",
      severity: "Critical",
      affectedPath: file.path,
      description: "A well-known default username/password pair was found in this file.",
      evidence: mask(match[0]),
      confidence: "high",
      recommendation: "Remove default credentials and require a unique password to be set before the device becomes operational.",
      cve: null,
      component: null,
      componentVersion: null,
      detectionSource: "default-credential pair match",
      isMalwareIndicator: false,
    });
    break; // one default-credential finding per file is enough signal
  }

  return findings;
}

// ---------------------------------------------------------------------------
// Certificates / keys — distinguish private key, public key, cert, CA cert
// ---------------------------------------------------------------------------

function detectKeyMaterial(file: AnalyzedFile, content: string): SecurityFinding[] {
  const findings: SecurityFinding[] = [];

  // Private keys are already covered by detectCredentials (Critical). Here we
  // handle the material that is NOT inherently a secret, so it is not
  // over-scored the way a bare "certificate detected" rule would.
  if (/-----BEGIN PUBLIC KEY-----/.test(content)) {
    findings.push({
      category: "Sensitive Information Exposure",
      title: "Public key material found",
      severity: "Informational",
      affectedPath: file.path,
      description: "A public key was found. Public keys are not secret; this is recorded for inventory and trust-scope review.",
      evidence: "-----BEGIN PUBLIC KEY----- (informational)",
      confidence: "high",
      recommendation: "Confirm the key's purpose and that it is scoped to this device or a legitimate shared trust anchor.",
      cve: null,
      component: null,
      componentVersion: null,
      detectionSource: "PEM public key header",
      isMalwareIndicator: false,
    });
  }

  if (/-----BEGIN CERTIFICATE-----/.test(content)) {
    // A crude but honest CA heuristic: text-encoded certs sometimes carry a
    // "CA:TRUE" basic-constraints marker if dumped alongside their ASN.1
    // text form. We do not decode DER here, so anything we cannot positively
    // identify as a CA cert is reported as a leaf/unknown-scope certificate,
    // not upgraded to "CA" on a guess.
    const looksLikeCa = /CA:\s*TRUE/i.test(content);
    findings.push({
      category: "Sensitive Information Exposure",
      title: looksLikeCa ? "CA certificate found" : "Certificate found",
      severity: "Low",
      affectedPath: file.path,
      description: looksLikeCa
        ? "A certificate with a CA basic-constraints marker was found. A CA certificate embedded in firmware can be used to trust arbitrary issued certificates and deserves scope review."
        : "A certificate was found. Certificates are not secret by themselves, but embedded trust material should be reviewed for scope and rotation.",
      evidence: "-----BEGIN CERTIFICATE----- (content withheld)",
      confidence: looksLikeCa ? "medium" : "high",
      recommendation: looksLikeCa
        ? "Confirm this CA is intended to be trusted by the device and has a documented rotation and revocation path."
        : "Confirm the certificate is intended for this device and has a documented rotation path.",
      cve: null,
      component: null,
      componentVersion: null,
      detectionSource: "PEM certificate header",
      isMalwareIndicator: false,
    });
  }

  return findings;
}

// ---------------------------------------------------------------------------
// Configuration analysis — specific, named files get specific checks
// ---------------------------------------------------------------------------

interface ConfigCheck {
  /** Matched against the firmware-relative path (case-insensitive, substring). */
  pathPattern: RegExp;
  run: (file: AnalyzedFile, content: string) => SecurityFinding[];
}

function configFinding(
  file: AnalyzedFile,
  partial: Omit<SecurityFinding, "affectedPath" | "cve" | "component" | "componentVersion" | "isMalwareIndicator">,
): SecurityFinding {
  return {
    ...partial,
    affectedPath: file.path,
    cve: null,
    component: null,
    componentVersion: null,
    isMalwareIndicator: false,
  };
}

const CONFIG_CHECKS: readonly ConfigCheck[] = Object.freeze([
  // /etc/passwd — accounts with UID 0 other than root are a privilege issue.
  {
    pathPattern: /(^|\/)etc\/passwd$/,
    run(file, content) {
      const findings: SecurityFinding[] = [];
      for (const line of content.split("\n")) {
        const fields = line.split(":");
        if (fields.length < 7) continue;
        const [user, , uid, , , , shell] = fields;
        if (user && user !== "root" && uid === "0") {
          findings.push(
            configFinding(file, {
              category: "Insecure Configuration",
              title: `Non-root account "${user}" has UID 0`,
              severity: "Critical",
              description: "An account other than root has UID 0, granting it full root privileges under a different name.",
              evidence: `${user}:x:0:...`,
              confidence: "high",
              recommendation: "Remove UID-0 aliasing for non-root accounts; grant elevated privileges through sudo/capabilities instead.",
              detectionSource: "/etc/passwd UID analysis",
            }),
          );
        }
        if (shell && /sh$/.test(shell.trim()) && user === "root" && !fields[1]?.includes("*") && fields[1] !== "x") {
          // A password hash inline in passwd (rather than "x" delegating to
          // shadow) means the hash sits in a world-readable file.
          findings.push(
            configFinding(file, {
              category: "Insecure Configuration",
              title: "Root password hash stored in world-readable /etc/passwd",
              severity: "High",
              description: "The root account's password hash is stored directly in /etc/passwd rather than being shadowed, so it is readable by any local user or process.",
              evidence: "root:<hash present>:0:0:...",
              confidence: "medium",
              recommendation: "Move password hashes to /etc/shadow (mode 0600, root-owned) and use 'x' in /etc/passwd.",
              detectionSource: "/etc/passwd shadow-delegation check",
            }),
          );
        }
      }
      return findings;
    },
  },
  // /etc/shadow — empty hash fields mean passwordless login.
  {
    pathPattern: /(^|\/)etc\/shadow$/,
    run(file, content) {
      const findings: SecurityFinding[] = [];
      for (const line of content.split("\n")) {
        const fields = line.split(":");
        if (fields.length < 2) continue;
        const [user, hash] = fields;
        if (!user) continue;
        // "!" and "*" (and prefixed variants like "!!") mean the account is
        // locked/disabled — genuinely not a finding. An EMPTY field is the
        // opposite: it means no password is required at all, which is the
        // case this check exists to catch. These must not be collapsed into
        // one skip condition.
        const isLocked = hash === "!" || hash === "*" || hash?.startsWith("!") === true;
        if (isLocked) continue;
        if (hash !== undefined && hash.length === 0) {
          findings.push(
            configFinding(file, {
              category: "Insecure Configuration",
              title: `Account "${user}" has an empty password hash`,
              severity: "Critical",
              description: "This account's shadow entry has an empty password field, which permits login with no password on many PAM configurations.",
              evidence: `${user}::...`,
              confidence: "high",
              recommendation: "Set a strong password hash for this account or disable it.",
              detectionSource: "/etc/shadow empty-hash check",
            }),
          );
        } else if (hash?.startsWith("$1$")) {
          findings.push(
            configFinding(file, {
              category: "Weak Cryptography",
              title: `Account "${user}" uses MD5-crypt ($1$) password hashing`,
              severity: "Medium",
              description: "MD5-crypt is fast to brute-force on modern hardware compared to bcrypt/sha512-crypt/yescrypt.",
              evidence: `${user}:$1$...`,
              confidence: "high",
              recommendation: "Re-hash passwords with sha512-crypt ($6$) or yescrypt where supported.",
              detectionSource: "/etc/shadow hash-algorithm check",
            }),
          );
        }
      }
      // File permissions on shadow itself matter independently of content.
      const mode = file.permissions ? Number.parseInt(file.permissions, 8) : null;
      if (mode !== null && (mode & 0o077) !== 0) {
        findings.push(
          configFinding(file, {
            category: "Excessive/Unsafe File Permissions",
            title: "/etc/shadow is readable or writable beyond the owner",
            severity: "High",
            description: `/etc/shadow has mode ${file.permissions}; it should be readable only by root (0600 or 0640).`,
            evidence: `permissions ${file.permissions}`,
            confidence: "high",
            recommendation: "Set /etc/shadow to mode 0600 (or 0640 with a trusted shadow group) owned by root.",
            detectionSource: "/etc/shadow permission check",
          }),
        );
      }
      return findings;
    },
  },
  // sshd_config / dropbear — weak remote-access settings.
  {
    pathPattern: /(^|\/)etc\/(ssh\/sshd_config|dropbear\/.*\.conf|default\/dropbear)$/,
    run(file, content) {
      const findings: SecurityFinding[] = [];
      if (/^\s*PermitRootLogin\s+yes\b/im.test(content)) {
        findings.push(
          configFinding(file, {
            category: "Insecure Configuration",
            title: "SSH root login is permitted",
            severity: "High",
            description: "PermitRootLogin yes allows direct root login over SSH, removing the audit trail an intermediate account would provide and widening the attack surface for credential stuffing.",
            evidence: "PermitRootLogin yes",
            confidence: "high",
            recommendation: "Set PermitRootLogin to 'no' or 'prohibit-password' and require sudo for administrative access.",
            detectionSource: "sshd_config directive scan",
          }),
        );
      }
      if (/^\s*PasswordAuthentication\s+yes\b/im.test(content)) {
        findings.push(
          configFinding(file, {
            category: "Insecure Configuration",
            title: "SSH password authentication is enabled",
            severity: "Medium",
            description: "Password authentication is more susceptible to credential stuffing and brute force than key-based authentication.",
            evidence: "PasswordAuthentication yes",
            confidence: "high",
            recommendation: "Disable password authentication and require public-key authentication.",
            detectionSource: "sshd_config directive scan",
          }),
        );
      }
      if (/DROPBEAR_EXTRA_ARGS=.*-w\b/.test(content) || /-w\b.*dropbear/i.test(content)) {
        findings.push(
          configFinding(file, {
            category: "Insecure Configuration",
            title: "Dropbear is configured to allow root login",
            severity: "High",
            description: "Dropbear's -w flag (or its absence) controls whether root login is refused; this configuration does not refuse it.",
            evidence: "dropbear root-login flag not set to refuse",
            confidence: "medium",
            recommendation: "Pass -w to dropbear to refuse root logins, or restrict root SSH login through another mechanism.",
            detectionSource: "dropbear argument scan",
          }),
        );
      }
      return findings;
    },
  },
  // OpenWrt UCI-style config files.
  {
    pathPattern: /(^|\/)etc\/config\//,
    run(file, content) {
      const findings: SecurityFinding[] = [];
      if (/option\s+enabled\s+['"]?1['"]?/i.test(content) && /telnet/i.test(file.path)) {
        findings.push(
          configFinding(file, {
            category: "Insecure Network Services",
            title: "Telnet is enabled in UCI configuration",
            severity: "High",
            description: "The UCI configuration enables a telnet service. Telnet transmits credentials and session data in plaintext.",
            evidence: "option enabled '1' (telnet)",
            confidence: "high",
            recommendation: "Disable telnet and use SSH with key-based authentication instead.",
            detectionSource: "UCI config directive scan",
          }),
        );
      }
      const passwordOption = /option\s+(?:password|key)\s+['"]([^'"]+)['"]/i.exec(content);
      if (passwordOption) {
        findings.push(
          configFinding(file, {
            category: "Hardcoded Credentials",
            title: "Password or key stored in UCI configuration",
            severity: "High",
            description: "A password or key value is stored directly in a UCI configuration file.",
            evidence: `option password '${mask(passwordOption[1] ?? "")}'`,
            confidence: "medium",
            recommendation: "Move secrets out of UCI config into a protected store, or require first-boot configuration.",
            detectionSource: "UCI config option scan",
          }),
        );
      }
      return findings;
    },
  },
  // inittab / init.d — startup-time service exposure and dangerous commands.
  {
    pathPattern: /(^|\/)etc\/(inittab|init\.d\/)/,
    run(file, content) {
      const findings: SecurityFinding[] = [];
      const telnetStart = /telnetd\b/i.exec(content);
      if (telnetStart) {
        findings.push(
          configFinding(file, {
            category: "Insecure Network Services",
            title: "Telnet service started at boot",
            severity: "High",
            description: "A telnetd invocation was found in a startup script, indicating the service is configured to run automatically.",
            evidence: telnetStart[0].slice(0, 160),
            confidence: "high",
            detectionSource: "startup-script scan",
            recommendation: "Remove or disable the automatic telnetd startup and use SSH instead.",
          }),
        );
      }
      const chmodWorld = /chmod\s+(?:-\w+\s+)*0?777\b/.exec(content);
      if (chmodWorld) {
        findings.push(
          configFinding(file, {
            category: "Dangerous Commands/Code Execution Indicators",
            title: "Startup script sets world-writable permissions",
            severity: "Medium",
            description: "A startup script applies mode 777 to a path, which is broader than almost any service needs.",
            evidence: chmodWorld[0],
            confidence: "medium",
            detectionSource: "startup-script command scan",
            recommendation: "Use the minimum permission mode the target actually requires.",
          }),
        );
      }
      // wget/curl piped straight into a shell is a real remote-code-execution
      // pattern, unlike wget merely being present on the system.
      const fetchExec = /(wget|curl)[^\n|]{0,200}\|\s*(?:sh|bash|ash)\b/i.exec(content);
      if (fetchExec) {
        findings.push(
          configFinding(file, {
            category: "Dangerous Commands/Code Execution Indicators",
            title: "Startup script pipes a remote download directly into a shell",
            severity: "High",
            description: "A downloader's output is piped directly into a shell interpreter at startup. This pattern lets whatever the remote endpoint serves execute unauthenticated code on boot.",
            evidence: fetchExec[0].slice(0, 160),
            confidence: "high",
            detectionSource: "startup-script fetch-and-execute pattern",
            recommendation: "Verify a signature or checksum before executing any downloaded content, and pin the source to a trusted, integrity-protected endpoint.",
          }),
        );
      }
      return findings;
    },
  },
]);

// ---------------------------------------------------------------------------
// Network services — evidence-based, one finding per service
// ---------------------------------------------------------------------------

const SERVICE_PROFILES: readonly {
  name: string;
  binaryPattern: RegExp;
  startupPattern: RegExp;
  baseSeverity: SecurityFinding["severity"];
  note: string;
}[] = Object.freeze([
  { name: "Telnet", binaryPattern: /(^|\/)telnetd$/, startupPattern: /telnetd\b/i, baseSeverity: "High", note: "Telnet transmits credentials and traffic in plaintext." },
  { name: "FTP", binaryPattern: /(^|\/)(vsftpd|proftpd|ftpd|bftpd)$/, startupPattern: /\b(vsftpd|proftpd|ftpd|bftpd)\b/i, baseSeverity: "High", note: "FTP transmits credentials in plaintext and has a history of directory-traversal vulnerabilities." },
  { name: "Dropbear SSH", binaryPattern: /(^|\/)dropbear(multi)?$/, startupPattern: /dropbear\b/i, baseSeverity: "Low", note: "SSH itself is not inherently unsafe; review the configuration checks reported separately." },
  { name: "OpenSSH", binaryPattern: /(^|\/)sshd$/, startupPattern: /\bsshd\b/i, baseSeverity: "Low", note: "SSH itself is not inherently unsafe; review the configuration checks reported separately." },
  { name: "uhttpd", binaryPattern: /(^|\/)uhttpd$/, startupPattern: /\buhttpd\b/i, baseSeverity: "Low", note: "A web-based admin interface exists; confirm it is not exposed on a WAN-facing interface." },
  { name: "lighttpd", binaryPattern: /(^|\/)lighttpd$/, startupPattern: /\blighttpd\b/i, baseSeverity: "Low", note: "A web server is present; confirm it is not exposed on a WAN-facing interface." },
]);

function detectNetworkServices(files: readonly AnalyzedFile[], startupText: Map<string, string>): SecurityFinding[] {
  const findings: SecurityFinding[] = [];

  for (const service of SERVICE_PROFILES) {
    const binaryFile = files.find((file) => service.binaryPattern.test(file.path));
    if (!binaryFile) continue; // no evidence the service exists at all — report nothing

    let configuredIn: string | null = null;
    for (const [path, content] of startupText) {
      if (service.startupPattern.test(content)) {
        configuredIn = path;
        break;
      }
    }

    const severity = configuredIn ? service.baseSeverity : service.baseSeverity === "High" ? "Medium" : "Informational";

    findings.push({
      category: "Insecure Network Services",
      title: `${service.name} service ${configuredIn ? "is configured to start automatically" : "binary present (startup configuration not confirmed)"}`,
      severity,
      affectedPath: binaryFile.path,
      description:
        `${service.note} ` +
        (configuredIn
          ? `A startup reference was found in ${configuredIn}, indicating the service is configured to run.`
          : "The binary is present, but no startup-script reference was found, so it is not confirmed to run automatically. Network exposure could not be determined from static analysis alone."),
      evidence: configuredIn ? `binary: ${binaryFile.path}; startup reference: ${configuredIn}` : `binary: ${binaryFile.path}`,
      confidence: configuredIn ? "medium" : "low",
      recommendation: service.baseSeverity === "High"
        ? `Disable ${service.name} unless required, and replace it with an encrypted alternative.`
        : `Confirm ${service.name} is not exposed on an untrusted interface and is kept up to date.`,
      cve: null,
      component: service.name,
      componentVersion: null,
      detectionSource: configuredIn ? "binary + startup-script evidence" : "binary presence only",
      isMalwareIndicator: false,
    });
  }

  return findings;
}

// ---------------------------------------------------------------------------
// Weak cryptography — per file, not a single global match
// ---------------------------------------------------------------------------

const WEAK_CRYPTO_PATTERN = /\b(SSLv2|SSLv3|TLSv1\.0|TLSv1\.1|RC4|DES-CBC|3DES|MD5|SHA1)\b/;

function detectWeakCrypto(file: AnalyzedFile, content: string): SecurityFinding[] {
  const match = WEAK_CRYPTO_PATTERN.exec(content);
  if (!match) return [];
  return [
    {
      category: "Weak Cryptography",
      title: `Legacy cryptographic primitive referenced: ${match[1]}`,
      severity: /SSLv2|SSLv3|RC4|DES/.test(match[1]!) ? "High" : "Medium",
      affectedPath: file.path,
      description: "A legacy protocol, cipher, or digest name was found in this file. Static analysis cannot confirm it is actually negotiated at runtime.",
      evidence: match[0],
      confidence: "low",
      recommendation: "Verify whether this component enables the legacy primitive and migrate to a currently supported protocol/cipher/digest.",
      cve: null,
      component: null,
      componentVersion: null,
      detectionSource: "legacy-cryptography string scan",
      isMalwareIndicator: false,
    },
  ];
}

// ---------------------------------------------------------------------------
// Dangerous commands — context matters, not bare presence
// ---------------------------------------------------------------------------

/**
 * Utilities that are completely unremarkable on their own. Their presence is
 * not reported; only specific dangerous *usage patterns* (see CONFIG_CHECKS'
 * fetchExec rule, and reverse-shell patterns below) are findings.
 */
function detectExecutionIndicators(file: AnalyzedFile, content: string): SecurityFinding[] {
  const findings: SecurityFinding[] = [];

  // Classic reverse-shell one-liners — genuinely suspicious wherever found.
  const reverseShell = /\b(?:nc|ncat|netcat)\s+-[a-z]*e\b|\/bin\/(?:sh|bash)\s+-i\s+.{0,20}>&\s*\/dev\/tcp\//i.exec(content);
  if (reverseShell) {
    findings.push({
      category: "Dangerous Commands/Code Execution Indicators",
      title: "Reverse-shell command pattern found",
      severity: "Critical",
      affectedPath: file.path,
      description: "A command pattern consistent with spawning a reverse shell was found in this file.",
      evidence: reverseShell[0].slice(0, 160),
      confidence: "high",
      recommendation: "Treat this file as a strong backdoor indicator. Investigate its origin and how it is invoked before deploying this firmware.",
      cve: null,
      component: null,
      componentVersion: null,
      detectionSource: "reverse-shell pattern scan",
      isMalwareIndicator: true,
    });
  }

  // A hardcoded, non-loopback, non-private IP alongside a download command is
  // a callback-style indicator worth flagging — again, context, not presence.
  const callbackDownload = /(?:wget|curl)\s+[^\n]{0,40}https?:\/\/(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/i.exec(content);
  if (callbackDownload) {
    const ip = callbackDownload[1]!;
    const isPrivate = /^(10\.|127\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.)/.test(ip);
    if (!isPrivate) {
      findings.push({
        category: "Dangerous Commands/Code Execution Indicators",
        title: "Download command targets a hardcoded public IP address",
        severity: "Medium",
        affectedPath: file.path,
        description: "A wget/curl invocation targets a hardcoded public IP address rather than a domain name. This is a common pattern in firmware backdoors and botnet loaders, though it also appears in legitimate embedded update logic.",
        evidence: callbackDownload[0].slice(0, 160),
        confidence: "medium",
        recommendation: "Confirm the destination is a legitimate, expected update or telemetry endpoint for this device.",
        cve: null,
        component: null,
        componentVersion: null,
        detectionSource: "hardcoded-IP download pattern scan",
        isMalwareIndicator: true,
      });
    }
  }

  return findings;
}

// ---------------------------------------------------------------------------
// Driver
// ---------------------------------------------------------------------------

export interface SecurityAnalysisResult {
  findings: SecurityFinding[];
  malwareIndicatorCount: number;
}

/**
 * Run the full detection engine over an extracted filesystem.
 *
 * `root` is the sandbox root the files were extracted into; `files` is the
 * static-analysis inventory (already carries permissions, entropy, and
 * suspicious flags computed from real filesystem attributes).
 */
export async function runSecurityAnalysis(root: string, files: readonly AnalyzedFile[]): Promise<SecurityAnalysisResult> {
  const findings: SecurityFinding[] = [];
  const startupText = new Map<string, string>();

  // Only script/text/config-shaped files are worth reading as text; ELF
  // binaries are handled through their printable strings elsewhere and
  // reading megabytes of binary as latin1 here would be wasted work.
  const textualFiles = files.filter(
    (file) =>
      file.sizeBytes > 0 &&
      file.sizeBytes < 2 * 1024 * 1024 &&
      !file.type.startsWith("symlink") &&
      (file.type === "text" || file.type === "script (shebang)" || /\/etc\//.test(file.path) || /\.(conf|cfg|config|ini|json|xml|sh)$/i.test(file.path)),
  );

  for (const file of textualFiles) {
    const content = await readTextSample(root, file);
    if (content.length === 0) continue;

    findings.push(...detectCredentials(file, content));
    findings.push(...detectKeyMaterial(file, content));
    findings.push(...detectWeakCrypto(file, content));
    findings.push(...detectExecutionIndicators(file, content));

    for (const check of CONFIG_CHECKS) {
      if (check.pathPattern.test(file.path)) {
        findings.push(...check.run(file, content));
      }
    }
    if (/(^|\/)etc\/(inittab|init\.d\/)/.test(file.path)) {
      startupText.set(file.path, content);
    }
  }

  findings.push(...detectNetworkServices(files, startupText));

  // Surface the permission/entropy/symlink-escape work static-analysis.ts
  // already computed. Previously these were persisted on scan_files but
  // never turned into a finding, so real evidence never reached the analyst.
  for (const file of files) {
    if (!file.suspicious || !file.suspiciousReason) continue;
    const isPermissionIssue = /setuid|setgid|world-writable/i.test(file.suspiciousReason);
    findings.push({
      category: isPermissionIssue ? "Excessive/Unsafe File Permissions" : "Other Security Weaknesses",
      title: isPermissionIssue ? "File has unsafe permission bits" : "File flagged by static heuristics",
      severity: /setuid/i.test(file.suspiciousReason) ? "High" : "Medium",
      affectedPath: file.path,
      description: `Static analysis of this file's on-disk attributes raised a flag: ${file.suspiciousReason}.`,
      evidence: `${file.path} (${file.permissions ?? "unknown mode"}): ${file.suspiciousReason}`,
      confidence: "high",
      recommendation: isPermissionIssue
        ? "Remove unnecessary setuid/setgid/world-write bits; grant only the privilege the binary actually requires."
        : "Review this file's purpose and origin; the flag is a static heuristic, not confirmation of malicious intent.",
      cve: null,
      component: null,
      componentVersion: null,
      detectionSource: "filesystem attribute analysis (static-analysis.ts)",
      isMalwareIndicator: false,
    });
  }

  const malwareIndicatorCount = findings.filter((finding) => finding.isMalwareIndicator).length;
  return { findings, malwareIndicatorCount };
}
