#!/usr/bin/env node
/**
 * generate-tasks.js — Reusable Task Manifest Generator
 *
 * Takes a domain config JSON file and produces:
 *   1. A .tasks manifest file for task-runner.sh
 *   2. Individual prompt .md files for each task
 *
 * Usage:
 *   node scripts/generate-tasks.js configs/domain-01-iam.json
 *   node scripts/generate-tasks.js configs/domain-05-providers.json
 *
 * Config format: see configs/*.json
 *
 * Language awareness:
 *   The config JSON's top-level "language" field (default: "typescript")
 *   controls how test templates are generated in prompts and how the
 *   verify-tests.sh language parameter is set. Supported values:
 *   typescript, python, go, rust, java
 *
 * Test enforcement:
 *   When a task has a `tests` array AND a `testFile` field, the generator
 *   auto-appends a verify-tests.sh check to the verify command. This ensures
 *   the task fails if the expected test cases are missing from the output.
 *
 *   Config fields:
 *     tests:    string[]  — List of test descriptions (it('...') lines)
 *     testFile: string    — Path to the test file that must contain them
 *
 *   If `tests` is present but `testFile` is omitted, the generator extracts
 *   the test file path from the verify command (first argument to vitest run).
 */

const fs = require('fs');
const path = require('path');

const configPath = process.argv[2];
if (!configPath) {
  console.error('Usage: node scripts/generate-tasks.js <config-file>');
  process.exit(1);
}

const config = JSON.parse(fs.readFileSync(configPath, 'utf-8'));

// --- Language Configuration ---
const SUPPORTED_LANGUAGES = ['typescript', 'python', 'go', 'rust', 'java'];
const language = config.language || 'typescript';

if (!SUPPORTED_LANGUAGES.includes(language)) {
  console.error(`Warning: Unknown language "${language}", defaulting to typescript.`);
  console.error(`Supported: ${SUPPORTED_LANGUAGES.join(', ')}`);
}

/**
 * Language-specific test template configuration.
 */
const LANG_PRESETS = {
  typescript: {
    fencedLang: 'typescript',
    testPattern: "it('...')/test('...')",
    assertPattern: 'expect()/assert()',
    testTemplate: (desc) => `  it('${desc}', async () => { /* implement */ });`,
    countLabel: '`it()` / `test()`',
    assertLabel: '`expect()` / `assert()`',
  },
  python: {
    fencedLang: 'python',
    testPattern: 'def test_*()',
    assertPattern: 'assert / self.assert*',
    testTemplate: (desc) => {
      const funcName = 'test_' + desc.toLowerCase().replace(/[^a-z0-9]+/g, '_').replace(/_+$/, '');
      return `    def ${funcName}(self):\n        # implement\n        pass`;
    },
    countLabel: '`def test_*()` functions',
    assertLabel: '`assert` / `self.assert*` / `pytest.raises`',
  },
  go: {
    fencedLang: 'go',
    testPattern: 'func Test*(t *testing.T)',
    assertPattern: 'assert.*/require.*/t.Error/t.Fatal',
    testTemplate: (desc) => {
      const funcName = 'Test' + desc.replace(/[^a-zA-Z0-9]+/g, ' ')
        .split(' ').map(w => w.charAt(0).toUpperCase() + w.slice(1)).join('');
      return `func ${funcName}(t *testing.T) {\n\t// implement\n}`;
    },
    countLabel: '`func Test*` functions',
    assertLabel: '`assert.*` / `require.*` / `t.Error` / `t.Fatal`',
  },
  rust: {
    fencedLang: 'rust',
    testPattern: '#[test]',
    assertPattern: 'assert!/assert_eq!/assert_ne!',
    testTemplate: (desc) => {
      const funcName = desc.toLowerCase().replace(/[^a-z0-9]+/g, '_').replace(/_+$/, '');
      return `#[test]\nfn ${funcName}() {\n    // implement\n}`;
    },
    countLabel: '`#[test]` annotations',
    assertLabel: '`assert!` / `assert_eq!` / `assert_ne!`',
  },
  java: {
    fencedLang: 'java',
    testPattern: '@Test',
    assertPattern: 'assert*/verify/assertThat',
    testTemplate: (desc) => {
      const methodName = desc.replace(/[^a-zA-Z0-9]+/g, ' ')
        .split(' ').map((w, i) => i === 0 ? w.toLowerCase() : w.charAt(0).toUpperCase() + w.slice(1)).join('');
      return `@Test\npublic void ${methodName}() {\n    // implement\n}`;
    },
    countLabel: '`@Test` annotations',
    assertLabel: '`assert*()` / `verify()` / `assertThat()`',
  },
};

const langPreset = LANG_PRESETS[language] || LANG_PRESETS.typescript;

// --- Paths ---
const outputDir = path.resolve(__dirname, '..'); // project root
const tasksDir = path.join(outputDir, 'scripts', 'tasks');
const promptsDir = path.join(tasksDir, 'prompts', config.promptPrefix);

fs.mkdirSync(promptsDir, { recursive: true });

// --- Helpers ---

/**
 * Extract the test file path from a vitest verify command.
 * e.g., "pnpm --filter api vitest run src/domains/provider/provider.test.ts"
 *   → "src/domains/provider/provider.test.ts"
 */
function extractTestFileFromVerify(verify) {
  // Match the path after "vitest run "
  const match = verify.match(/vitest\s+run\s+(.+?)(?:\s|$)/);
  if (match) {
    return match[1].trim();
  }
  // Also try pytest pattern: pytest path/to/test.py
  const pytestMatch = verify.match(/pytest\s+(.+?)(?:\s|$)/);
  if (pytestMatch) {
    return pytestMatch[1].trim();
  }
  // go test: go test -run TestSomething ./path/...
  const goTestMatch = verify.match(/go\s+test\s+.*?(\.\/.+?)(?:\s|$)/);
  if (goTestMatch) {
    return goTestMatch[1].trim();
  }
  return null;
}

/**
 * Build the compound verify command.
 * Original verify + test count enforcement via verify-tests.sh.
 */
function buildVerifyCommand(task) {
  if (!task.tests || task.tests.length === 0) {
    return task.verify;
  }

  const testFile = task.testFile || extractTestFileFromVerify(task.verify);
  if (!testFile) {
    // Can't determine test file — fall back to original verify only
    return task.verify;
  }

  const minTests = task.tests.length;
  // Append language parameter for non-typescript languages
  const langArg = language !== 'typescript' ? ` ${language}` : '';
  return `${task.verify} && ./scripts/verify-tests.sh ${testFile} ${minTests}${langArg}`;
}

// --- Generate Manifest ---
const manifestLines = [];
manifestLines.push(`# ============================================================================`);
manifestLines.push(`# Domain ${config.domainNumber}: ${config.domainName} — Build Tasks`);
manifestLines.push(`# Run: ./scripts/task-runner.sh tasks/${config.manifestFile}`);
manifestLines.push(`#`);
manifestLines.push(`# Format: TASK_ID | DESCRIPTION | PROMPT_FILE | VERIFY_COMMAND`);
manifestLines.push(`# Language: ${language}`);
manifestLines.push(`# Generated: ${new Date().toISOString().split('T')[0]}`);
manifestLines.push(`# ============================================================================`);
manifestLines.push('');

for (const section of config.sections) {
  manifestLines.push(`## ${section.title}`);
  manifestLines.push('');
  for (const task of section.tasks) {
    const promptPath = `tasks/prompts/${config.promptPrefix}/${task.id}.md`;
    const verifyCmd = buildVerifyCommand(task);
    manifestLines.push(`${task.id} | ${task.description} | ${promptPath} | ${verifyCmd}`);
  }
  manifestLines.push('');
}

const manifestPath = path.join(tasksDir, config.manifestFile);
fs.writeFileSync(manifestPath, manifestLines.join('\n'));
console.log(`Manifest: ${manifestPath}`);

// --- Generate Prompt Files ---
let promptCount = 0;
let testEnforcedCount = 0;

for (const section of config.sections) {
  for (const task of section.tasks) {
    const lines = [];

    // Header
    lines.push(`# Task ${task.id}: ${task.description}`);
    lines.push('');

    // What to build
    lines.push('## What to Build');
    lines.push('');
    if (Array.isArray(task.build)) {
      for (const line of task.build) lines.push(line);
    } else {
      lines.push(task.build);
    }
    lines.push('');

    // Project context (injected from PROJECT_CONTEXT.md sections)
    if (task.context) {
      lines.push('## Project Context');
      lines.push('');
      if (Array.isArray(task.context)) {
        for (const line of task.context) lines.push(line);
      } else {
        lines.push(task.context);
      }
      lines.push('');
    }

    // FRD Reference
    if (task.frd) {
      lines.push('## FRD Reference');
      lines.push('');
      if (Array.isArray(task.frd)) {
        for (const line of task.frd) lines.push(line);
      } else {
        lines.push(task.frd);
      }
      lines.push('');
    }

    // Security rules
    if (task.security) {
      lines.push('## Critical Security Rules');
      lines.push('');
      for (const rule of task.security) {
        lines.push(`- ${rule}`);
      }
      lines.push('');
    }

    // Dependencies / prerequisites
    if (task.depends && task.depends.length > 0) {
      lines.push('## Prerequisites');
      lines.push('');
      lines.push(`This task depends on the following completed tasks: ${task.depends.join(', ')}`);
      lines.push('');
    }

    // Tests — language-aware templates
    if (task.tests && task.tests.length > 0) {
      const testFile = task.testFile || extractTestFileFromVerify(task.verify);
      const minTests = task.tests.length;

      lines.push('## Required Tests (MANDATORY)');
      lines.push('');
      lines.push(`You MUST write ALL ${minTests} of the following tests. The verification step will count ${langPreset.countLabel} in the test file and fail if fewer than ${minTests} exist. Skipping or omitting tests will cause this task to fail.`);
      lines.push('');
      if (testFile) {
        lines.push(`**Test file:** \`${testFile}\``);
        lines.push('');
      }
      lines.push(`\`\`\`${langPreset.fencedLang}`);
      for (const test of task.tests) {
        lines.push(langPreset.testTemplate(test));
      }
      lines.push('```');
      lines.push('');
      lines.push(`**Total required: ${minTests} test(s).** Do not output [TASK_COMPLETE] until all ${minTests} tests are written and passing.`);
      lines.push('');
      testEnforcedCount++;
    }

    // Verify command (show the compound version so Claude knows what's enforced)
    const verifyCmd = buildVerifyCommand(task);
    lines.push('## Run After Completion');
    lines.push('');
    lines.push('```bash');
    lines.push(verifyCmd);
    lines.push('```');
    lines.push('');
    lines.push('All tests must pass before outputting [TASK_COMPLETE].');

    const promptPath = path.join(promptsDir, `${task.id}.md`);
    fs.writeFileSync(promptPath, lines.join('\n'));
    promptCount++;
  }
}

console.log(`Prompts: ${promptCount} files in ${promptsDir}`);
console.log(`Test-enforced tasks: ${testEnforcedCount} of ${promptCount}`);
console.log(`Language: ${language}`);
console.log('Done.');
