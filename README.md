# ai-code-smell

Detect suspicious AI-generated code patterns before they become maintenance
problems.

## Usage

```bash
npm install
npx ai-code-smell scan src/
```

When installed globally or linked locally:

```bash
ai-code-smell scan src/
```

Example output:

```txt
Possible hallucinated API:
fs.readJsonSync is not exposed by Node's fs module in src/config.ts:1
Did you mean fs.readFileSync + JSON.parse?
```

The scanner exits with:

- `0` when no suspicious patterns are found
- `1` when findings are reported
- `2` for usage or filesystem errors

## Detectors

The MVP includes heuristic detectors for:

- over-broad try/catch blocks
- fake validation
- unused abstractions
- hallucinated APIs
- excessive comments
- regex monstrosities
- security theater
- tests that assert implementation details only
