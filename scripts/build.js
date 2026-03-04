#!/usr/bin/env node

/**
 * BeforeMerge Build Script
 *
 * Compiles individual rule markdown files into a single AGENTS.md document
 * that AI coding agents can consume for code review.
 *
 * Usage: node scripts/build.js [skill-name]
 * Example: node scripts/build.js nextjs-review
 *
 * If no skill name is provided, builds all skills.
 */

const fs = require('fs')
const path = require('path')

// ─── Configuration ───────────────────────────────────────────────────────────

const SKILLS_DIR = path.join(__dirname, '..', 'skills')

const SECTION_ORDER = {
  sec: { priority: 1, label: 'Security Anti-Patterns', impact: 'CRITICAL' },
  perf: { priority: 2, label: 'Performance Patterns', impact: 'HIGH' },
  arch: { priority: 3, label: 'Architecture Patterns', impact: 'MEDIUM' },
  qual: { priority: 4, label: 'Code Quality', impact: 'LOW-MEDIUM' },
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

function parseFrontmatter(content) {
  const match = content.match(/^---\n([\s\S]*?)\n---\n([\s\S]*)$/)
  if (!match) return { meta: {}, body: content }

  const meta = {}
  match[1].split('\n').forEach((line) => {
    const [key, ...rest] = line.split(':')
    if (key && rest.length) {
      let value = rest.join(':').trim()
      // Strip surrounding quotes from scalar values
      if ((value.startsWith('"') && value.endsWith('"')) ||
          (value.startsWith("'") && value.endsWith("'"))) {
        value = value.slice(1, -1)
      }
      // Parse arrays: [tag1, tag2] or ["CWE-862", "CWE-20"]
      if (value.startsWith('[') && value.endsWith(']')) {
        value = value
          .slice(1, -1)
          .split(',')
          .map((s) => {
            s = s.trim()
            // Strip quotes from array elements
            if ((s.startsWith('"') && s.endsWith('"')) ||
                (s.startsWith("'") && s.endsWith("'"))) {
              s = s.slice(1, -1)
            }
            return s
          })
      }
      meta[key.trim()] = value
    }
  })

  return { meta, body: match[2].trim() }
}

function collectRuleFiles(rulesDir) {
  const rules = []

  if (!fs.existsSync(rulesDir)) return rules

  // Walk subdirectories (security/, performance/, etc.)
  const entries = fs.readdirSync(rulesDir, { withFileTypes: true })

  for (const entry of entries) {
    if (entry.isDirectory()) {
      const subdir = path.join(rulesDir, entry.name)
      const files = fs.readdirSync(subdir).filter((f) => f.endsWith('.md'))

      for (const file of files) {
        const content = fs.readFileSync(path.join(subdir, file), 'utf-8')
        const { meta, body } = parseFrontmatter(content)
        const prefix = file.split('-')[0]

        rules.push({
          file,
          prefix,
          category: entry.name,
          meta,
          body,
        })
      }
    } else if (entry.name.endsWith('.md') && !entry.name.startsWith('_')) {
      // Top-level rule files (not _template.md, _sections.md)
      const content = fs.readFileSync(path.join(rulesDir, entry.name), 'utf-8')
      const { meta, body } = parseFrontmatter(content)
      const prefix = entry.name.split('-')[0]

      rules.push({
        file: entry.name,
        prefix,
        category: 'uncategorized',
        meta,
        body,
      })
    }
  }

  return rules
}

function buildAgentsMd(skillDir, skillName) {
  const rulesDir = path.join(skillDir, 'rules')
  const metadataPath = path.join(skillDir, 'metadata.json')

  // Load metadata
  let metadata = {}
  if (fs.existsSync(metadataPath)) {
    metadata = JSON.parse(fs.readFileSync(metadataPath, 'utf-8'))
  }

  // Collect all rules
  const rules = collectRuleFiles(rulesDir)

  // Sort by section priority, then alphabetically
  rules.sort((a, b) => {
    const aPriority = SECTION_ORDER[a.prefix]?.priority ?? 99
    const bPriority = SECTION_ORDER[b.prefix]?.priority ?? 99
    if (aPriority !== bPriority) return aPriority - bPriority
    return a.file.localeCompare(b.file)
  })

  // Build the document
  const lines = []

  lines.push(`# BeforeMerge: ${skillName}`)
  lines.push('')

  if (metadata.abstract) {
    lines.push(metadata.abstract)
    lines.push('')
  }

  // Table of Contents
  lines.push('## Table of Contents')
  lines.push('')

  let currentSection = null
  let ruleIndex = 0

  for (const rule of rules) {
    const section = SECTION_ORDER[rule.prefix]
    const sectionKey = rule.prefix

    if (sectionKey !== currentSection) {
      currentSection = sectionKey
      if (section) {
        lines.push(
          `### ${section.priority}. ${section.label} (${section.impact})`
        )
      }
    }

    ruleIndex++
    const title = rule.meta.title || rule.file.replace('.md', '')
    const impact = rule.meta.impact || ''
    const cwe = rule.meta.cwe ? ` [${rule.meta.cwe}]` : ''
    lines.push(`- ${ruleIndex}. ${title} — ${impact}${cwe}`)
  }

  lines.push('')
  lines.push('---')
  lines.push('')

  // Full rules
  lines.push('## Rules')
  lines.push('')

  for (const rule of rules) {
    lines.push(rule.body)
    lines.push('')
    lines.push('---')
    lines.push('')
  }

  // Footer
  lines.push(`*Generated by BeforeMerge build script on ${new Date().toISOString().split('T')[0]}.*`)
  lines.push(`*Version: ${metadata.version || '0.0.0'} | Rules: ${rules.length}*`)

  return lines.join('\n')
}

// ─── Main ────────────────────────────────────────────────────────────────────

function main() {
  const targetSkill = process.argv[2]
  const skills = fs.readdirSync(SKILLS_DIR, { withFileTypes: true })
    .filter((d) => d.isDirectory())
    .filter((d) => !targetSkill || d.name === targetSkill)

  if (skills.length === 0) {
    console.error(`No skills found${targetSkill ? ` matching "${targetSkill}"` : ''}.`)
    process.exit(1)
  }

  for (const skill of skills) {
    const skillDir = path.join(SKILLS_DIR, skill.name)
    const rulesDir = path.join(skillDir, 'rules')

    if (!fs.existsSync(rulesDir)) {
      console.log(`Skipping ${skill.name} (no rules/ directory)`)
      continue
    }

    console.log(`Building ${skill.name}...`)

    const agentsMd = buildAgentsMd(skillDir, skill.name)
    const outputPath = path.join(skillDir, 'AGENTS.md')

    fs.writeFileSync(outputPath, agentsMd, 'utf-8')

    const ruleCount = (agentsMd.match(/^## /gm) || []).length
    const size = (Buffer.byteLength(agentsMd) / 1024).toFixed(1)

    console.log(`  → ${outputPath} (${size} KB)`)
  }

  console.log('Done.')
}

main()
