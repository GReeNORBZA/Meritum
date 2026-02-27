#!/usr/bin/env node
/**
 * extract-frd.js — One-time FRD .docx to .md Extractor
 *
 * Reads each .docx file in docs/frd/ and writes extracted paragraph text
 * to docs/frd/extracted/ as .md files. These extracted files are referenced
 * when building the help-centre config JSON for prompt embedding.
 *
 * Requires: python3 with python-docx installed
 *
 * Usage:
 *   node scripts/extract-frd.js
 */

const fs = require('fs');
const path = require('path');
const { execSync } = require('child_process');

const frdDir = path.resolve(__dirname, '..', 'docs', 'frd');
const outputDir = path.join(frdDir, 'extracted');

fs.mkdirSync(outputDir, { recursive: true });

// Write the Python extraction script to a temp file to avoid shell escaping issues
const pyScript = path.join(outputDir, '_extract.py');
fs.writeFileSync(pyScript, `
import docx
import sys

doc = docx.Document(sys.argv[1])
for para in doc.paragraphs:
    text = para.text.strip()
    if text:
        style = para.style.name if para.style else ''
        if style.startswith('Heading 1'):
            print('# ' + text)
        elif style.startswith('Heading 2'):
            print('## ' + text)
        elif style.startswith('Heading 3'):
            print('### ' + text)
        elif style.startswith('Heading 4'):
            print('#### ' + text)
        else:
            print(text)
        print()

for table in doc.tables:
    header = True
    for row in table.rows:
        cells = [cell.text.strip().replace('\\n', ' ') for cell in row.cells]
        print('| ' + ' | '.join(cells) + ' |')
        if header:
            print('| ' + ' | '.join(['---'] * len(cells)) + ' |')
            header = False
    print()
`);

const files = fs.readdirSync(frdDir).filter(f => f.endsWith('.docx'));

if (files.length === 0) {
  console.error('No .docx files found in docs/frd/');
  fs.unlinkSync(pyScript);
  process.exit(1);
}

console.log(`Found ${files.length} .docx files in ${frdDir}`);

let extracted = 0;

for (const file of files) {
  const inputPath = path.join(frdDir, file);
  const baseName = file.replace(/\.docx$/, '');
  const outputPath = path.join(outputDir, `${baseName}.md`);

  console.log(`  Extracting: ${file}`);

  try {
    const result = execSync(
      `python3 "${pyScript}" "${inputPath}"`,
      { encoding: 'utf-8', maxBuffer: 10 * 1024 * 1024 }
    );
    fs.writeFileSync(outputPath, `# ${baseName}\n\n${result}`);
    extracted++;
  } catch (err) {
    console.error(`  ERROR extracting ${file}: ${err.message}`);
  }
}

// Clean up temp python script
fs.unlinkSync(pyScript);

console.log(`\nExtracted ${extracted}/${files.length} files to ${outputDir}/`);
