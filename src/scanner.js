import { promises as fs } from 'node:fs';
import path from 'node:path';

const SOURCE_EXTENSIONS = new Set([
  '.cjs',
  '.cts',
  '.js',
  '.jsx',
  '.mjs',
  '.mts',
  '.ts',
  '.tsx'
]);

const IGNORED_DIRECTORIES = new Set([
  '.git',
  'coverage',
  'dist',
  'node_modules'
]);

const HALLUCINATED_APIS = [
  {
    pattern: /\bfs\.readJsonSync\s*\(/,
    api: 'fs.readJsonSync',
    module: "Node's fs module",
    suggestion: 'Did you mean fs.readFileSync + JSON.parse?'
  },
  {
    pattern: /\bfs\.readJson\s*\(/,
    api: 'fs.readJson',
    module: "Node's fs module",
    suggestion: 'Did you mean fs.promises.readFile + JSON.parse?'
  },
  {
    pattern: /\bArray\.flatten\s*\(/,
    api: 'Array.flatten',
    module: "JavaScript's Array constructor",
    suggestion: 'Did you mean array.flat()?'
  },
  {
    pattern: /\bJSON\.parseAsync\s*\(/,
    api: 'JSON.parseAsync',
    module: "JavaScript's JSON object",
    suggestion: 'Did you mean JSON.parse on awaited text?'
  }
];

const SECURITY_SENSITIVE_RANDOM_ASSIGNMENT =
  /(?:^|[;{]\s*)(?:(?:const|let|var)\s+)?(?:token|secret|password|apiKey|apikey|key)\b\s*=\s*[^;\n]*\bMath\.random\s*\(/i;

const SECURITY_THEATER = [
  {
    pattern: /\bbtoa\s*\(\s*(password|secret|token|apiKey|apikey|key)\b/i,
    message: 'Base64 encoding sensitive values is not encryption.',
    suggestion: 'Use a vetted password hashing or encryption primitive for the threat model.'
  },
  {
    pattern: SECURITY_SENSITIVE_RANDOM_ASSIGNMENT,
    message: 'Math.random is not suitable for security-sensitive values.',
    suggestion: 'Use crypto.randomBytes or crypto.getRandomValues.'
  }
];

const EMPTY_CATCH_BODY_PATTERN = /^\s*(?:\/\/.*)?\s*$/;
const ERROR_SWALLOW_PATTERN = /\b(return\s+(?:null|undefined|false|\[\]|\{\})|console\.(?:log|warn|error))\b/;
const IMPLEMENTATION_DETAIL_ASSERTION_PATTERN = /\b(?:expect|assert)\b[^\n]*(?:mock\.calls|\._private\b|\.internal\b)/g;

export async function scanPath(targetPath) {
  const absoluteTarget = path.resolve(targetPath);
  const files = await collectSourceFiles(absoluteTarget);
  const findings = [];

  for (const file of files) {
    const source = await fs.readFile(file, 'utf8');
    findings.push(...scanSource(source, file));
  }

  return findings.sort((a, b) => a.file.localeCompare(b.file) || a.line - b.line);
}

export function scanSource(source, file = '<inline>') {
  const lines = source.split(/\r?\n/);
  return [
    ...detectHallucinatedApis(lines, file),
    ...detectOverBroadTryCatch(source, file),
    ...detectFakeValidation(lines, file),
    ...detectUnusedAbstractions(source, file),
    ...detectExcessiveComments(lines, file),
    ...detectRegexMonstrosities(lines, file),
    ...detectSecurityTheater(lines, file),
    ...detectImplementationDetailTests(source, file)
  ];
}

async function collectSourceFiles(target) {
  const stat = await fs.stat(target);

  if (stat.isFile()) {
    return SOURCE_EXTENSIONS.has(path.extname(target)) ? [target] : [];
  }

  if (!stat.isDirectory()) {
    return [];
  }

  const entries = await fs.readdir(target, { withFileTypes: true });
  const files = [];

  for (const entry of entries) {
    if (entry.isDirectory() && IGNORED_DIRECTORIES.has(entry.name)) {
      continue;
    }

    const entryPath = path.join(target, entry.name);
    if (entry.isDirectory()) {
      files.push(...await collectSourceFiles(entryPath));
    } else if (entry.isFile() && SOURCE_EXTENSIONS.has(path.extname(entry.name))) {
      files.push(entryPath);
    }
  }

  return files;
}

function detectHallucinatedApis(lines, file) {
  const findings = [];

  lines.forEach((line, index) => {
    for (const api of HALLUCINATED_APIS) {
      if (api.pattern.test(line)) {
        findings.push({
          title: 'Possible hallucinated API',
          message: `${api.api} is not exposed by ${api.module}`,
          suggestion: api.suggestion,
          file,
          line: index + 1
        });
      }
    }
  });

  return findings;
}

function detectOverBroadTryCatch(source, file) {
  const findings = [];
  const tryCatchPattern = /try\s*\{[\s\S]*?\}\s*catch\s*\(([^)]*)\)\s*\{([\s\S]*?)\}/g;

  for (const match of source.matchAll(tryCatchPattern)) {
    const catchName = match[1].trim();
    const catchBody = match[2];
    const line = lineNumberForIndex(source, match.index);
    const catchUsesError = catchName && new RegExp(`\\b${escapeRegExp(catchName)}\\b`).test(catchBody);
    const swallowsError = EMPTY_CATCH_BODY_PATTERN.test(catchBody)
      || ERROR_SWALLOW_PATTERN.test(catchBody);

    if (!catchUsesError || swallowsError) {
      findings.push({
        title: 'Over-broad try/catch',
        message: 'Catch block appears to swallow or under-handle errors',
        suggestion: 'Catch specific failures and preserve useful error context.',
        file,
        line
      });
    }
  }

  return findings;
}

function detectFakeValidation(lines, file) {
  const findings = [];
  const fakePatterns = [
    /\b(validate|isValid|verify|check)[A-Za-z0-9_]*\s*\([^)]*\)\s*\{?\s*return\s+true\s*;?\s*\}?/i,
    /if\s*\([^)]*(?:TODO|valid|validate)[^)]*\)\s*\{\s*\}/i,
    /if\s*\([^)]*\)\s*\{\s*\/[/*]\s*(?:TODO|validate|validation)/i
  ];

  lines.forEach((line, index) => {
    if (fakePatterns.some((pattern) => pattern.test(line))) {
      findings.push({
        title: 'Fake validation',
        message: 'Validation branch appears to accept input without checking it',
        suggestion: 'Assert concrete constraints or remove misleading validation.',
        file,
        line: index + 1
      });
    }
  });

  return findings;
}

function detectUnusedAbstractions(source, file) {
  const findings = [];
  const abstractionPattern = /\b(?:class|interface|abstract\s+class)\s+([A-Z][A-Za-z0-9_]*)/g;

  for (const match of source.matchAll(abstractionPattern)) {
    const name = match[1];
    const uses = source.match(new RegExp(`\\b${escapeRegExp(name)}\\b`, 'g')) ?? [];

    if (uses.length === 1 && /(?:Base|Manager|Service|Factory|Provider|Wrapper)$/.test(name)) {
      findings.push({
        title: 'Unused abstraction',
        message: `${name} is declared but not referenced elsewhere`,
        suggestion: 'Remove unused layers or connect them to real call sites.',
        file,
        line: lineNumberForIndex(source, match.index)
      });
    }
  }

  return findings;
}

function detectExcessiveComments(lines, file) {
  const codeLines = lines.filter((line) => line.trim() && !line.trim().startsWith('*')).length;
  const commentLines = lines.filter((line) => /^\s*(\/\/|\/\*|\*)/.test(line)).length;

  if (codeLines >= 20 && commentLines / codeLines > 0.45) {
    return [{
      title: 'Excessive comments',
      message: 'Comment density is unusually high for the amount of code',
      suggestion: 'Prefer clearer names and focused comments that explain why, not every step.',
      file,
      line: 1
    }];
  }

  return [];
}

function detectRegexMonstrosities(lines, file) {
  const findings = [];

  lines.forEach((line, index) => {
    const regexLiteral = line.match(/\/(?:\\.|[^/\\\n]){80,}\/[gimsuyd]*/);
    const nestedGroups = (line.match(/\([^)]*[+*][^)]*\)[+*{]/g) ?? []).length;

    if (regexLiteral || nestedGroups >= 2) {
      findings.push({
        title: 'Regex monstrosity',
        message: 'Regular expression is long or contains nested repetition',
        suggestion: 'Split the parser into named steps or document and test the expression thoroughly.',
        file,
        line: index + 1
      });
    }
  });

  return findings;
}

function detectSecurityTheater(lines, file) {
  const findings = [];

  lines.forEach((line, index) => {
    const code = stripLineComment(line);
    for (const smell of SECURITY_THEATER) {
      if (smell.pattern.test(code)) {
        findings.push({
          title: 'Security theater',
          message: smell.message,
          suggestion: smell.suggestion,
          file,
          line: index + 1
        });
      }
    }
  });

  return findings;
}

function detectImplementationDetailTests(source, file) {
  if (!/\.(?:test|spec)\.[cm]?[jt]sx?$/.test(file)) {
    return [];
  }

  const detailAssertions = source.match(IMPLEMENTATION_DETAIL_ASSERTION_PATTERN) ?? [];

  if (detailAssertions.length < 2) {
    return [];
  }

  return [{
    title: 'Implementation-detail test',
    message: 'Test mostly asserts private calls or internal details',
    suggestion: 'Prefer assertions about observable behavior.',
    file,
    line: lineNumberForIndex(source, source.indexOf(detailAssertions[0]))
  }];
}

function lineNumberForIndex(source, index) {
  return source.slice(0, index).split(/\r?\n/).length;
}

function escapeRegExp(value) {
  return value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

function stripLineComment(line) {
  return line.replace(/\s*\/\/.*$/, '');
}
