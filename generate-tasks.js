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
 */

const fs = require('fs');
const path = require('path');

const configPath = process.argv[2];
if (!configPath) {
  console.error('Usage: node scripts/generate-tasks.js <config-file>');
  process.exit(1);
}

const config = JSON.parse(fs.readFileSync(configPath, 'utf-8'));

// --- Paths ---
const outputDir = path.resolve(__dirname, '..'); // project root
const tasksDir = path.join(outputDir, 'scripts', 'tasks');
const promptsDir = path.join(tasksDir, 'prompts', config.promptPrefix);

fs.mkdirSync(promptsDir, { recursive: true });

// --- Generate Manifest ---
const manifestLines = [];
manifestLines.push(`# ============================================================================`);
manifestLines.push(`# Domain ${config.domainNumber}: ${config.domainName} — Build Tasks`);
manifestLines.push(`# Run: ./scripts/task-runner.sh tasks/${config.manifestFile}`);
manifestLines.push(`#`);
manifestLines.push(`# Format: TASK_ID | DESCRIPTION | PROMPT_FILE | VERIFY_COMMAND`);
manifestLines.push(`# Generated: ${new Date().toISOString().split('T')[0]}`);
manifestLines.push(`# ============================================================================`);
manifestLines.push('');

for (const section of config.sections) {
  manifestLines.push(`## ${section.title}`);
  manifestLines.push('');
  for (const task of section.tasks) {
    const promptPath = `tasks/prompts/${config.promptPrefix}/${task.id}.md`;
    manifestLines.push(`${task.id} | ${task.description} | ${promptPath} | ${task.verify}`);
  }
  manifestLines.push('');
}

const manifestPath = path.join(tasksDir, config.manifestFile);
fs.writeFileSync(manifestPath, manifestLines.join('\n'));
console.log(`Manifest: ${manifestPath}`);

// --- Generate Prompt Files ---
let promptCount = 0;
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
    if (task.depends) {
      lines.push('## Prerequisites');
      lines.push('');
      lines.push(`This task depends on the following completed tasks: ${task.depends.join(', ')}`);
      lines.push('');
    }

    // Tests to write
    if (task.tests) {
      lines.push('## Tests to Write');
      lines.push('');
      lines.push('```typescript');
      for (const test of task.tests) {
        lines.push(`  it('${test}');`);
      }
      lines.push('```');
      lines.push('');
    }

    // Verify command
    lines.push('## Run After Completion');
    lines.push('');
    lines.push('```bash');
    lines.push(task.verify);
    lines.push('```');
    lines.push('');
    lines.push('All tests must pass before outputting [TASK_COMPLETE].');

    const promptPath = path.join(promptsDir, `${task.id}.md`);
    fs.writeFileSync(promptPath, lines.join('\n'));
    promptCount++;
  }
}

console.log(`Prompts: ${promptCount} files in ${promptsDir}`);
console.log('Done.');
