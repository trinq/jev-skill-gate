import { readFileSync, readdirSync, statSync, existsSync } from "node:fs";
import { join, extname, basename } from "node:path";

const IGNORED_DIRS = new Set([
  "node_modules",
  ".git",
  ".venv",
  "venv",
  "__pycache__",
  ".idea",
  ".vscode",
  ".claude",
  "dist",
  "build",
  ".cache",
]);

const IGNORED_DOC_BASENAMES = new Set([
  "readme",
  "license",
  "changelog",
  "contributing",
  "code_of_conduct",
  "security",
]);

const SENSITIVE_PARAM_MAP = [
  { regex: /\b(url|uri|redirect|redirect_uri|callback|dest|destination|target|endpoint|proxy|feed)\s*=/i, tag: "ssrf", param: "$1=" },
  { regex: /\b(file|filename|path|filepath|doc|document|page|folder|root|dir|template_file)\s*=/i, tag: "path-traversal", param: "$1=" },
  { regex: /\b(user_id|account_id|profile_id|order_id|doc_id|uid|uuid|account|user|id)\s*=/i, tag: "idor", param: "$1=" },
  { regex: /\b(query|search|sql|filter|sort|order|keyword|by)\s*=/i, tag: "sqli", param: "$1=" },
  { regex: /\b(template|tpl|view|layout|render)\s*=/i, tag: "ssti", param: "$1=" },
  { regex: /\b(cmd|exec|command|ping|host|ip|run|shell)\s*=/i, tag: "command-injection", param: "$1=" },
  { regex: /\b(next|return_to|goto|r)\s*=/i, tag: "open-redirect", param: "$1=" },
];

const SECURITY_KEYWORD_MAP = [
  { keywords: ["ssrf", "server-side request forgery", "metadata", "169.254.169.254", "internal network", "intranet", "cloud metadata", "webhook"], tag: "ssrf" },
  { keywords: ["path traversal", "directory traversal", "traversal", "lfi", "local file inclusion", "etc/passwd", "dot dot slash", "duyệt thư mục", "đọc file", "../", "..%2f"], tag: "path-traversal" },
  { keywords: ["sqli", "sql injection", "union select", "blind sql", "chèn sql", "tiêm sql", "information_schema", "sleep("], tag: "sqli" },
  { keywords: ["xss", "cross-site scripting", "<script>", "alert(", "reflected xss", "stored xss", "dom xss", "chèn script"], tag: "xss" },
  { keywords: ["idor", "insecure direct object reference", "broken access control", "bypassing authorization", "horizontal privilege", "phân quyền"], tag: "idor" },
  { keywords: ["rce", "remote code execution", "command injection", "reverse shell", "reverse_shell", "thực thi lệnh", "os command", "shell injection"], tag: "command-injection" },
  { keywords: ["ssti", "server-side template injection", "template injection", "jinja2", "jinja", "twig", "freemarker", "mako", "{{", "${"], tag: "ssti" },
  { keywords: ["open redirect", "redirect bypass", "chuyển hướng"], tag: "open-redirect" },
  { keywords: ["auth bypass", "authentication bypass", "jwt", "broken auth", "privilege escalation", "session fixation", "bearer", "oauth", "leo thang đặc quyền"], tag: "auth-bypass" },
  { keywords: ["s3 bucket", "s3:", "aws", "azure blob", "gcp bucket", "cloud storage", "iam role", "cloud misconfig"], tag: "cloud-misconfig" },
  { keywords: ["subdomain", "port scan", "enumeration", "ffuf", "amass", "nmap", "sublist3r", "recon", "reconnaissance", "osint"], tag: "recon" },
  { keywords: ["graphql", "introspection", "swagger", "api security", "rest api", "api endpoint"], tag: "api-security" },
  { keywords: ["race condition", "toctou", "concurrency", "race"], tag: "race-condition" },
  { keywords: ["file upload", "webshell", "mime type", "multipart", "tải lên file"], tag: "file-upload" },
  { keywords: ["deserialization", "insecure deserialization", "pickle", "unserialize", "yaml load", "object injection"], tag: "deserialization" },
];

const PYTHON_EXPLOIT_PATTERNS = [
  { regex: /\bpayload\s*=/i, name: "payload", tag: null },
  { regex: /\bshell\s*=/i, name: "shell", tag: "command-injection" },
  { regex: /\breverse_shell\b/i, name: "reverse_shell", tag: "command-injection" },
  { regex: /\bbase64\.(?:b64)?decode\b/i, name: "base64.decode", tag: null },
  { regex: /\bos\.(?:system|popen)\b/i, name: "os.system", tag: "command-injection" },
  { regex: /\bsubprocess\.(?:Popen|run|call|check_output)\b/i, name: "subprocess", tag: "command-injection" },
  { regex: /\b(?:eval|exec)\s*\(/i, name: "eval/exec", tag: "command-injection" },
  { regex: /\brequests\.(?:get|post|put|delete|patch|head|options)\b/i, name: "requests.http", tag: null },
  { regex: /\b(?:pwntools|pwn)\b/i, name: "pwntools", tag: "command-injection" },
];

const ENDPOINT_REGEX = /(?:(?:\b(?:GET|POST|PUT|DELETE|PATCH)\s+([/\w\-._~:?#[\]@!$&'()*+,;=]+))|(?:https?:\/\/[^\s"'<>]+)|(\/(?:api|v[0-9]|admin|auth|oauth|users?|account|download|view|file|upload|proxy|graphql|debug|internal|console)[^\s"'<>?]*\??[^\s"'<>]*))/gi;

function findFiles(dir, maxDepth, currentDepth = 0) {
  let notesFiles = [];
  let scriptFiles = [];

  let entries;
  try {
    entries = readdirSync(dir, { withFileTypes: true });
  } catch {
    return { notesFiles, scriptFiles };
  }

  for (const entry of entries) {
    if (entry.name.startsWith(".") && entry.name !== ".txt" && entry.name !== ".md") continue;

    const fullPath = join(dir, entry.name);

    if (entry.isDirectory()) {
      if (IGNORED_DIRS.has(entry.name)) continue;
      if (currentDepth < maxDepth) {
        const sub = findFiles(fullPath, maxDepth, currentDepth + 1);
        notesFiles = notesFiles.concat(sub.notesFiles);
        scriptFiles = scriptFiles.concat(sub.scriptFiles);
      }
    } else if (entry.isFile()) {
      const ext = extname(entry.name).toLowerCase();
      const base = basename(entry.name, ext).toLowerCase();

      if ((ext === ".txt" || ext === ".md") && !IGNORED_DOC_BASENAMES.has(base)) {
        notesFiles.push(fullPath);
      } else if (ext === ".py" && base !== "setup") {
        scriptFiles.push(fullPath);
      }
    }
  }

  return { notesFiles, scriptFiles };
}

function readFileSlice(filePath, maxBytes) {
  try {
    const fd = readFileSync(filePath, { flag: "r" });
    const slice = fd.subarray(0, maxBytes);
    return slice.toString("utf8");
  } catch {
    return "";
  }
}

/**
 * Scans a project/workspace directory for bug bounty and security testing indicators.
 * Looks into notes files (.txt, .md) and exploit scripts (.py).
 */
export function collectSecuritySignals(projectDir = process.cwd(), options = {}) {
  if (options.enabled === false) return null;

  const maxNotes = options.maxNotesFiles ?? 20;
  const maxScripts = options.maxScriptFiles ?? 10;
  const maxBytes = options.maxFileSizeBytes ?? 4096;
  const scanDepth = options.scanDepth ?? 1;

  if (!existsSync(projectDir)) return null;

  const { notesFiles, scriptFiles } = findFiles(projectDir, scanDepth);

  const targetNotes = notesFiles.slice(0, maxNotes);
  const targetScripts = scriptFiles.slice(0, maxScripts);

  if (targetNotes.length === 0 && targetScripts.length === 0) {
    return null;
  }

  const tags = new Set();
  const detectedParams = new Set();
  const detectedKeywords = new Set();
  const endpoints = new Set();
  const exploitPatterns = new Set();
  const notesTextSnippets = [];

  // 1. Process notes files
  for (const filePath of targetNotes) {
    const content = readFileSlice(filePath, maxBytes);
    if (!content) continue;

    const lower = content.toLowerCase();
    let hasNoteIndicator = false;

    // Check sensitive parameters
    for (const mapping of SENSITIVE_PARAM_MAP) {
      const match = lower.match(mapping.regex);
      if (match) {
        const paramName = `${match[1].toLowerCase()}=`;
        detectedParams.add(paramName);
        tags.add(mapping.tag);
        hasNoteIndicator = true;
      }
    }

    // Check keywords
    for (const mapping of SECURITY_KEYWORD_MAP) {
      for (const kw of mapping.keywords) {
        if (lower.includes(kw.toLowerCase())) {
          detectedKeywords.add(kw);
          tags.add(mapping.tag);
          hasNoteIndicator = true;
          break;
        }
      }
    }

    // Extract endpoints
    let epMatch;
    ENDPOINT_REGEX.lastIndex = 0;
    while ((epMatch = ENDPOINT_REGEX.exec(content)) !== null) {
      const ep = (epMatch[1] || epMatch[2] || epMatch[0]).trim();
      if ((ep.startsWith("/") || ep.startsWith("http://") || ep.startsWith("https://")) && ep.length > 2 && ep.length < 200) {
        endpoints.add(ep);
        hasNoteIndicator = true;
      }
      if (endpoints.size >= 25) break;
    }

    if (hasNoteIndicator) {
      notesTextSnippets.push(content.slice(0, 500).replace(/\s+/g, " ").trim());
    }
  }

  // 2. Process Python scripts
  for (const filePath of targetScripts) {
    const content = readFileSlice(filePath, maxBytes);
    if (!content) continue;

    for (const pat of PYTHON_EXPLOIT_PATTERNS) {
      if (pat.regex.test(content)) {
        exploitPatterns.add(pat.name);
        if (pat.tag) tags.add(pat.tag);
      }
    }

    // Check sensitive parameters inside Python script strings too
    const lower = content.toLowerCase();
    for (const mapping of SENSITIVE_PARAM_MAP) {
      const match = lower.match(mapping.regex);
      if (match) {
        const paramName = `${match[1].toLowerCase()}=`;
        detectedParams.add(paramName);
        tags.add(mapping.tag);
      }
    }

    // Check keywords in script
    for (const mapping of SECURITY_KEYWORD_MAP) {
      for (const kw of mapping.keywords) {
        if (lower.includes(kw.toLowerCase())) {
          detectedKeywords.add(kw);
          tags.add(mapping.tag);
          break;
        }
      }
    }
  }

  // If no security context, no params, no security keywords, and no exploit patterns
  if (tags.size === 0 && detectedParams.size === 0 && detectedKeywords.size === 0 && exploitPatterns.size === 0) {
    return null;
  }

  let notes_excerpt = notesTextSnippets.join(" ").slice(0, 1000).trim();

  return {
    security_context: Array.from(tags),
    detected_params: Array.from(detectedParams),
    detected_keywords: Array.from(detectedKeywords),
    endpoints: Array.from(endpoints).slice(0, 25),
    exploit_patterns: Array.from(exploitPatterns),
    notes_excerpt,
  };
}
