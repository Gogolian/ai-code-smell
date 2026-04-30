#!/usr/bin/env node

import { scanPath } from '../src/scanner.js';

const [, , command, target = '.'] = process.argv;

if (!command || command === '--help' || command === '-h') {
  console.log('Usage: ai-code-smell scan <path>');
  process.exit(0);
}

if (command !== 'scan') {
  console.error(`Unknown command: ${command}`);
  console.error('Usage: ai-code-smell scan <path>');
  process.exit(2);
}

try {
  const findings = await scanPath(target);

  if (findings.length === 0) {
    console.log('No suspicious AI code smells found.');
    process.exit(0);
  }

  for (const finding of findings) {
    console.log(`${finding.title}:`);
    console.log(`${finding.message} in ${finding.file}:${finding.line}`);
    if (finding.suggestion) {
      console.log(finding.suggestion);
    }
    console.log();
  }

  process.exit(1);
} catch (error) {
  console.error(error.message);
  process.exit(2);
}
