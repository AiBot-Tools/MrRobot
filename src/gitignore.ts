// Does <repo>/.gitignore ignore one entry directly under the repository root?
//
// CONTRACT
//
//   The question the kernel asks before it trusts an in-repo path: would
//   `git add -A` leave <repo>/.env (a file) or <repo>/.aos (a directory) out?
//   This reads the root .gitignore with git's rules (gitignore(5), and dir.c /
//   wildmatch.c where the man page is silent): comments, trailing-space
//   trimming, a line cut at its first NUL, `!` negation, a trailing `/` for
//   directories only, anchoring by an inner `/`, a leading run of `**/`, `*`,
//   `?`, bracket classes, and the last matching line wins.
//
//   Where this reading and git's could differ it answers "not ignored": a false
//   refusal costs the operator one .gitignore edit; a false "ignored" can put a
//   key or the event log into a public commit. So every line is judged twice,
//   once as git reads it with core.ignorecase=false and once with true (the
//   macOS default), and:
//
//     - an ignoring line counts only if it matches under BOTH, and only as
//       written once cut at its first NUL: a trailing CR is never stripped,
//       so `.env\r` does not count (git strips one; older readers may not).
//       A CR elsewhere, as in `.en[v\r]`, is an ordinary pattern character,
//       as git reads it;
//     - a negating line counts if it matches under EITHER, with or without
//       its CR;
//     - a pattern this does not model never ignores and always un-ignores:
//       an anchored pattern holding a bracket (git lets `/` sit inside one)
//       or a `**` that is not a whole leading segment (git's literal-prefix
//       rule lets `.e**/nv` match `.env`), a POSIX class like [[:alpha:]], an
//       unterminated `[`, a trailing `\`, an escaped `/`, and a line longer
//       than 4 KiB once cut at its NUL (matching costs memory in proportion
//       to the line: one 100 MiB line exhausts Node's default heap, so the
//       kernel would die at boot instead of refusing).
//
//   Also "not ignored": a symlinked .gitignore (git 2.32+ does not read one),
//   one of 100 MiB or more (git 2.50 drops a file whose size plus the newline
//   it appends exceeds 100 MiB, i.e. exactly these), and, for a
//   directory entry, a <repo>/<entry> that exists but is not a directory —
//   git judges a symlink as a file, so `/.aos/` does not cover it, and what is
//   written through it lands wherever it points.
//
//   Not consulted: .git/info/exclude and core.excludesFile. Both rank below the
//   root .gitignore for a root entry, so they can never undo its verdict; they
//   can only add ignores this check then fails to credit — the safe direction —
//   and a check that leaned on them would pass here and fail on the next clone.
//   Nor is the index: .gitignore does not apply to a tracked file, so a
//   force-added .env is caught by test/gitignore.test.ts, not here.

import { lstatSync, readFileSync } from 'node:fs'
import { join } from 'node:path'

/** git 2.50's PATTERN_MAX_FILE_SIZE: git reads a file only while its size + 1 (an appended newline) is at most this. */
const GIT_PATTERN_FILE_LIMIT = 100 * 1024 * 1024

/** The longest pattern modelled. git has no such limit; no one writes such a line, and longer ones are not modelled (see the contract). */
const MAX_MODELLED_LINE = 4096

type Token =
  | { readonly kind: 'lit'; readonly ch: string }
  | { readonly kind: 'one' }
  | { readonly kind: 'star' }
  | {
      readonly kind: 'class'
      readonly negated: boolean
      readonly singles: readonly string[]
      readonly ranges: readonly (readonly [string, string])[]
    }

/** True when the root .gitignore ignores `<repoRoot>/<entry>`; see the contract. */
export function rootGitignoreIgnores(repoRoot: string, entry: string, kind: 'file' | 'dir'): boolean {
  const path = join(repoRoot, '.gitignore')
  let text: string
  try {
    const st = lstatSync(path)
    if (!st.isFile() || st.size >= GIT_PATTERN_FILE_LIMIT) return false
    // latin1: one char per byte, as git's wildmatch sees it.
    text = readFileSync(path, 'latin1')
  } catch {
    return false
  }
  if (kind === 'dir') {
    try {
      if (!lstatSync(join(repoRoot, entry)).isDirectory()) return false
    } catch {
      // Absent: the directory git would ignore once it is created.
    }
  }
  if (text.startsWith('\xEF\xBB\xBF')) text = text.slice(3)

  let ignored = false
  for (const raw of text.split('\n')) {
    if (raw === '' || raw.startsWith('#')) continue
    if (raw.startsWith('!')) {
      const body = raw.slice(1)
      const forms = body.endsWith('\r') ? [body, body.slice(0, -1)] : [body]
      const couldMatch = forms.some((f) => [false, true].some((fold) => matches(cutAtNul(f), entry, kind, fold) !== false))
      if (couldMatch) ignored = false
    } else {
      const line = cutAtNul(raw)
      if (matches(line, entry, kind, false) === true && matches(line, entry, kind, true) === true) ignored = true
    }
  }
  return ignored
}

/** git reads a pattern with strlen: it ends at the first NUL. */
function cutAtNul(line: string): string {
  const nul = line.indexOf('\0')
  return nul === -1 ? line : line.slice(0, nul)
}

/**
 * Whether one pattern (without its `!`) matches a root entry, as git would
 * read it with core.ignorecase = `fold`: true, false, or undefined when the
 * pattern uses something this does not model.
 */
function matches(line: string, entry: string, kind: 'file' | 'dir', fold: boolean): boolean | undefined {
  if (line.length > MAX_MODELLED_LINE) return undefined
  let pattern = trimTrailingSpaces(line)
  if (pattern === undefined) return undefined
  if (pattern === '') return false
  let dirOnly = false
  if (pattern.endsWith('/')) {
    dirOnly = true
    pattern = pattern.slice(0, -1)
  }
  if (dirOnly && kind !== 'dir') return false
  if (pattern.includes('\\/')) return undefined

  // No separator: matched against the entry's name at any depth.
  if (!pattern.includes('/')) return segmentMatches(pattern, entry, fold)

  // Anchored. A bracket may hold the `/` that anchors it, which splitting on
  // `/` would get wrong: not modelled.
  const anchored = pattern.startsWith('/') ? pattern.slice(1) : pattern
  if (anchored.includes('[')) return undefined
  const segments = anchored.split('/')
  // A leading segment of two or more stars matches zero directories.
  while (segments.length > 1 && /^\*{2,}$/.test(segments[0] ?? '')) segments.shift()
  if (segments.length === 1) {
    const only = segments[0] ?? ''
    if (/^\*{2,}$/.test(only)) return true
    return segmentMatches(only, entry, fold)
  }
  // Still a separator to cross. Without a `**`, crossing one takes a `/` the
  // root entry's name does not have; with one, git's literal-prefix rule can
  // make it match zero directories mid-pattern: not modelled.
  return /\*{2,}/.test(anchored) ? undefined : false
}

/** git's trim_trailing_spaces: drop unescaped trailing spaces (not tabs). */
function trimTrailingSpaces(line: string): string | undefined {
  let lastSpace = -1
  for (let i = 0; i < line.length; i++) {
    const ch = line[i]
    if (ch === ' ') {
      if (lastSpace === -1) lastSpace = i
    } else if (ch === '\\') {
      i++
      if (i >= line.length) return undefined
      lastSpace = -1
    } else {
      lastSpace = -1
    }
  }
  return lastSpace === -1 ? line : line.slice(0, lastSpace)
}

function segmentMatches(pattern: string, name: string, fold: boolean): boolean | undefined {
  const tokens = tokenize(pattern)
  if (tokens === undefined) return undefined
  return globMatch(tokens, name, fold)
}

function tokenize(pattern: string): Token[] | undefined {
  const out: Token[] = []
  for (let i = 0; i < pattern.length; i++) {
    const ch = pattern[i] ?? ''
    if (ch === '\\') {
      const next = pattern[i + 1]
      if (next === undefined) return undefined
      out.push({ kind: 'lit', ch: next })
      i++
    } else if (ch === '*') {
      // Within one segment a run of stars is one star: the entry has no `/`.
      if (out.at(-1)?.kind !== 'star') out.push({ kind: 'star' })
    } else if (ch === '?') {
      out.push({ kind: 'one' })
    } else if (ch === '[') {
      const parsed = bracket(pattern, i)
      if (parsed === undefined) return undefined
      out.push(parsed.token)
      i = parsed.end
    } else {
      out.push({ kind: 'lit', ch })
    }
  }
  return out
}

/** A `[...]` class starting at `start`, read as wildmatch.c reads it; undefined for what is not modelled. */
function bracket(pattern: string, start: number): { token: Token; end: number } | undefined {
  let i = start + 1
  let negated = false
  if (pattern[i] === '!' || pattern[i] === '^') {
    negated = true
    i++
  }
  const singles: string[] = []
  const ranges: [string, string][] = []
  let first = true
  for (;;) {
    const ch = pattern[i]
    if (ch === undefined) return undefined
    if (ch === ']' && !first) break
    first = false
    let lo = ch
    if (ch === '\\') {
      const next = pattern[i + 1]
      if (next === undefined) return undefined
      lo = next
      i++
    } else if (ch === '[' && pattern[i + 1] === ':') {
      return undefined
    }
    if (pattern[i + 1] === '-' && pattern[i + 2] !== undefined && pattern[i + 2] !== ']') {
      let hi = pattern[i + 2] ?? ''
      i += 2
      if (hi === '\\') {
        const next = pattern[i + 1]
        if (next === undefined) return undefined
        hi = next
        i++
      }
      // wildmatch.c tests the start as a member before it reads the `-`, so a
      // reversed range like `z-a` still matches its first character.
      singles.push(lo)
      ranges.push([lo, hi])
    } else {
      singles.push(lo)
    }
    i++
  }
  return { token: { kind: 'class', negated, singles, ranges }, end: i }
}

function globMatch(tokens: readonly Token[], text: string, fold: boolean): boolean {
  const memo = new Map<number, boolean>()
  const at = (t: number, s: number): boolean => {
    const key = t * (text.length + 1) + s
    const seen = memo.get(key)
    if (seen !== undefined) return seen
    let result: boolean
    const token = tokens[t]
    if (token === undefined) result = s === text.length
    else if (token.kind === 'star') result = at(t + 1, s) || (s < text.length && at(t, s + 1))
    else if (s >= text.length) result = false
    else result = hit(token, text[s] ?? '', fold) && at(t + 1, s + 1)
    memo.set(key, result)
    return result
  }
  return at(0, 0)
}

const isUpper = (c: string): boolean => c >= 'A' && c <= 'Z'
const isLower = (c: string): boolean => c >= 'a' && c <= 'z'

/**
 * One token against one character, as wildmatch.c decides it. Under
 * WM_CASEFOLD the text character is lowered; a literal is lowered too; a class
 * member is compared with the lowered character as written (so `[E]` matches
 * neither case), and a range also accepts the character's upper case — which
 * is why a negated range like `[!A-Z]` matches 'e' only without folding.
 */
function hit(token: Exclude<Token, { kind: 'star' }>, ch: string, fold: boolean): boolean {
  if (token.kind === 'one') return true
  const t = fold && isUpper(ch) ? ch.toLowerCase() : ch
  if (token.kind === 'lit') return (fold && isUpper(token.ch) ? token.ch.toLowerCase() : token.ch) === t
  let matched = token.singles.includes(t)
  for (const [lo, hi] of token.ranges) {
    if (t >= lo && t <= hi) matched = true
    else if (fold && isLower(t)) {
      const up = t.toUpperCase()
      if (up >= lo && up <= hi) matched = true
    }
  }
  return matched !== token.negated
}
