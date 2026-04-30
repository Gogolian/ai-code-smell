import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, mkdir, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';

import { scanPath, scanSource } from '../src/scanner.js';

test('detects hallucinated fs readJsonSync API', () => {
  const findings = scanSource("const config = fs.readJsonSync('config.json');", 'src/config.ts');

  assert.equal(findings[0].title, 'Possible hallucinated API');
  assert.match(findings[0].message, /fs\.readJsonSync/);
  assert.equal(findings[0].line, 1);
});

test('detects representative suspicious code smells', () => {
  const source = `
function validateInput(value) { return true; }
try {
  risky();
} catch (error) {
  return null;
}
class EmptyManager {}
const token = Math.random().toString(36);
const bad = /(a+)+b*(c+)+d*/;
`;

  const titles = scanSource(source, 'src/example.ts').map((finding) => finding.title);

  assert.ok(titles.includes('Fake validation'));
  assert.ok(titles.includes('Over-broad try/catch'));
  assert.ok(titles.includes('Unused abstraction'));
  assert.ok(titles.includes('Security theater'));
  assert.ok(titles.includes('Regex monstrosity'));
});

test('detects implementation-detail tests', () => {
  const source = `
test('calls helpers', () => {
  expect(service._private).toHaveBeenCalledWith('x');
  expect(logger.internal).toHaveBeenCalledWith('y');
});
`;

  const findings = scanSource(source, 'src/example.test.ts');

  assert.equal(findings[0].title, 'Implementation-detail test');
});

test('scanPath recursively scans source files and ignores non-source files', async () => {
  const root = await mkdtemp(join(tmpdir(), 'ai-code-smell-'));
  await mkdir(join(root, 'src'));
  await writeFile(join(root, 'src', 'config.ts'), "const config = fs.readJson('config.json');");
  await writeFile(join(root, 'README.md'), 'fs.readJsonSync should not be scanned here');

  const findings = await scanPath(root);

  assert.equal(findings.length, 1);
  assert.match(findings[0].file, /config\.ts$/);
});
