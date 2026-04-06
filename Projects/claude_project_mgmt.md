# Zovark Project Management Reference

Quick lookup for all project management files.

---

## Files

| File | Purpose | When to Read |
|------|---------|-------------|
| Projects/Zovark_Roadmap.md | Master Kanban board — all work across all sprints | Session start, task selection |
| Projects/Sprint_C_Pipeline.md | Current sprint detail — C1/C2/C3 tasks and acceptance criteria | When working on Sprint C |
| Projects/ENGINEERING_PROCESS.md | How we ship — commit format, anti-patterns, quality gates, release process | Every session, before every commit |
| Projects/SESSION_PROTOCOL.md | Session start/end checklists, report template | Session start and end |
| Projects/claude_project_mgmt.md | This file — quick reference | When lost |

---

## Board Format

All Kanban boards use Obsidian Kanban plugin format:
- Frontmatter: `kanban-plugin: basic`
- Columns: `## Column Name`
- Tasks: `- [ ] description` (open) or `- [x] description` (done)
- Without Obsidian: renders as well-structured markdown

---

## Rules

1. **Never move a task to Done without 16/16 on verify_all.sh**
2. **Never start a new task if regression is already failing**
3. **Update the Kanban board BEFORE committing** (board reflects truth)
4. **One task = one commit** (logical changes, not file count)
5. **Decisions go in the Decision Log** (Zovark_Roadmap.md) with dates
6. **Blocked tasks stay in Blocked** with explicit blocker reason
7. **Constraints are non-negotiable** unless explicitly overridden by operator

---

## Workflow

```
1. Read Kanban board
2. Pick next unblocked task from In Progress (or move from Sprint column)
3. Read affected files (COMPONENT_REGISTRY.md tells you which)
4. Implement
5. verify_all.sh 16/16
6. Update board
7. Commit
8. Repeat
```
