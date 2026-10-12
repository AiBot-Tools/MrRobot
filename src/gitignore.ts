// Does <repo>/.gitignore ignore one entry directly under the repository root?
//
// CONTRACT
//
//   The question the kernel asks before it trusts an in-repo path: would
//   `git add -A` leave <repo>/.env (a file) or <repo>/.aos (a directory) out?
//   This reads the root .gitignore with git's rules from gitignore(5): comments,
//   trailing-space trimming, `!` negation, a trailing `/` for directories only,
//   anchoring by an inner `/`, `**`, `*`, `?`, bracket classes, and the last
//   matching line wins. Where this reading and git's could differ it answers
//   "not ignored": a false refusal costs the operator one .gitignore edit; a
//   false "ignored" can put a key or the event log into a public commit.
//
//   Fail-closed choices, each a place git's answer depends on more than the
//   text: an ignoring line counts only when it matches case-sensitively (git
//   folds case under core.ignorecase, the macOS default) and has no trailing CR;
//   a negating line counts when it matches under either case or with its CR
//   stripped; a construct this does not model (a POSIX class like [[:alpha:]],
//   an unterminated `[`, a trailing `\`, an escaped `/`) never ignores and
//   always un-ignores. A symlinked .gitignore is no .gitignore, as in git 2.32+.
//
//   Not consulted: .git/info/exclude and core.excludesFile. Both rank below the
//   root .gitignore for a root entry, so they can never undo its verdict; they
//   can only add ignores this check then fails to credit — the safe direction —
//   and a check that leaned on them would pass here and fail on the next clone.
//   Nor is the index: .gitignore does not apply to a tracked file, so a
//   force-added .env is caught by test/config-files.test.ts, not here.

import { lstatSync, readFileSync } from 'node:fs'
import { join } from 'node:path'

type Token =
  | { readonly kind: 'lit'; readonly ch: string }
  | { readonly kind: 'one' }
  | { readonly kind: 'star' }
  | { readonly kind: 'class'; readonly negated: boolean; readonly test: (ch: string) => boolean }

/** True when the root .gitignore ignores `<repoRoot>/<entry>`; see the contract. */
export function rootGitignoreIgnores(repoRoot: string, entry: string, kind: 'file' | 'dir'): boolean {
  const path = join(repoRoot, '.gitignore')
  let text: string
  try {
    if (!lstatSync(path).isFile()) return false
    // latin1: one char per byte, as git's wildmatch sees it.
    text = readFileSync(path, 'latin1')
  } catch {
    return false
  }
  if (text.startsWith('\xEF\xBB\xBF')) text = text.slice(3)

  let ignored = false
  for (const raw of text.split('\n')) {
    if (raw === '' || raw.startsWith('#')) continue
    const negated = raw.startsWith('!')
    if (negated) {
      const forms = raw.endsWith('\r') ? [raw.slice(1), raw.slice(1, -1)] : [raw.slice(1)]
      if (forms.some((f) => matches(f, entry, kind, true) !== false)) ignored = false
    } else if (matches(raw, entry, kind, false) === true) {
      ignored = true
    }
  }
  return ignored
}

/**
 * Whether one pattern (without its `!`) matches a root entry: true, false, or
 * undefined when the pattern uses something this does not model.
 */
function matches(line: string, entry: string, kind: 'file' | 'dir', foldCase: boolean): boolean | undefined {
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

  if (!pattern.includes('/')) return segmentMatches(pattern, entry, foldCase)

  // Anchored: relative to the root. A leading `**/` matches zero directories,
  // and any other separator needs a directory the root entry does not have.
  const segments = (pattern.startsWith('/') ? pattern.slice(1) : pattern).split('/')
  while (segments.length > 1 && segments[0] === '**') segments.shift()
  if (segments.length !== 1) return false
  const only = segments[0] ?? ''
  if (only === '**') return true
  return segmentMatches(only, entry, foldCase)
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

function segmentMatches(pattern: string, name: string, foldCase: boolean): boolean | undefined {
  const tokens = tokenize(pattern)
  if (tokens === undefined) return undefined
  const exact = globMatch(tokens, name, false)
  if (exact || !foldCase) return exact
  return globMatch(tokens, name, true)
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

/** A `[...]` class starting at `start`; undefined for what is not modelled. */
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
      ranges.push([lo, hi])
    } else {
      singles.push(lo)
    }
    i++
  }
  const test = (c: string): boolean => singles.includes(c) || ranges.some(([lo, hi]) => c >= lo && c <= hi)
  return { token: { kind: 'class', negated, test }, end: i }
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

/**
 * One token against one character. Folding is used only to widen what a
 * negating line matches, so each branch errs toward a match: a class tests
 * both cases, and a negated class only the lowered character.
 */
function hit(token: Exclude<Token, { kind: 'star' }>, ch: string, fold: boolean): boolean {
  if (token.kind === 'one') return true
  if (token.kind === 'lit') return fold ? token.ch.toLowerCase() === ch.toLowerCase() : token.ch === ch
  if (!fold) return token.test(ch) !== token.negated
  if (token.negated) return !token.test(ch.toLowerCase())
  return token.test(ch) || token.test(ch.toLowerCase()) || token.test(ch.toUpperCase())
}
