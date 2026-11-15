import test from 'node:test'
import assert from 'node:assert/strict'
import { DEFAULT_REFERENCE_TOKEN_BOUNDS, extractReferenceTokens, referenceTokens } from '../src/reference-query.ts'

// Pure Node tests: no plugin activation, network, dependency installation or
// cross-package imports. All fixture peer names, workspace names and paths are synthetic.

test('plain and quoted mentions retain the Host whitespace boundary and scoped packages', () => {
  assert.deepEqual(referenceTokens('read @studio:Notes/docs/a.md and @"studio:设计 笔记/设计.md"\n@laptop:plugin:@example/clock'), [
    'studio:Notes/docs/a.md', 'studio:设计 笔记/设计.md', 'laptop:plugin:@example/clock',
  ])
  assert.deepEqual(referenceTokens('@studio:one\t@studio:two\r\n@studio:three'), ['studio:one', 'studio:two', 'studio:three'])
})

test('email, escaped and non-whitespace embedded markers never become references', () => {
  assert.deepEqual(referenceTokens('mail user@studio:Notes (x@studio:Notes) \\@studio:Notes [@studio:Notes] @studio:real'), ['studio:real'])
})

test('missing quotes and malformed quoted suffixes never resolve partial references', () => {
  for (const malformed of ['@"studio:Notes', '@"studio:Notes"suffix', '@"studio:Notes"/suffix', '@""', '@"studio:Notes\ncontinued', '@studio:Notes"suffix']) {
    assert.deepEqual(referenceTokens(malformed), [], malformed)
  }
  assert.deepEqual(referenceTokens('@"studio:Notes" @studio:real'), ['studio:Notes', 'studio:real'])
  assert.deepEqual(referenceTokens('@"studio:broken\n@studio:real'), ['studio:real'])
})

test('only a final unclosed quoted directory follows the Host formatter exception', () => {
  assert.deepEqual(referenceTokens('@"studio:设计 笔记/docs/'), ['studio:设计 笔记/docs/'])
  assert.deepEqual(referenceTokens('@"studio:设计 笔记/docs/\n@studio:real'), ['studio:real'])
  assert.deepEqual(referenceTokens('@"studio:设计 笔记/docs/ more'), [])
  assert.deepEqual(extractReferenceTokens('@"studio:Notes/ more', { maxChars: 15 }).tokens, [])
})

test('single inline code never manufactures reference boundaries or query fragments', () => {
  assert.deepEqual(referenceTokens('`@studio:hidden` @studio:real'), ['studio:real'])
  assert.deepEqual(referenceTokens('@studio:fake`code` @studio:real'), ['studio:real'])
  assert.deepEqual(referenceTokens('`code`@studio:fake @studio:real'), ['studio:real'])
  assert.deepEqual(referenceTokens('@"studio:fake `code`" @studio:real'), ['studio:real'])
})

test('multiline inline code and exact multi-backtick delimiters are masked', () => {
  assert.deepEqual(referenceTokens('``first\n@studio:hidden\nlast`` @studio:real'), ['studio:real'])
  assert.deepEqual(referenceTokens('`first\n@studio:hidden\nlast` @studio:real'), ['studio:real'])
  assert.deepEqual(referenceTokens('``code with ` @studio:hidden`` @studio:real'), ['studio:real'])
  assert.deepEqual(referenceTokens('unclosed ` @studio:hidden\n@studio:real'), ['studio:real'])
})

test('fences retain opening character and delimiter length across inner short runs', () => {
  assert.deepEqual(referenceTokens('before @studio:one\n````ts\n@studio:hidden\n```\n@studio:also-hidden\n````\nafter @studio:two'), ['studio:one', 'studio:two'])
  assert.deepEqual(referenceTokens('~~~~text\n@studio:hidden\n~~~\n@studio:also-hidden\n~~~~\n@studio:real'), ['studio:real'])
  assert.deepEqual(referenceTokens('```\n@studio:hidden\n~~~\n@studio:also-hidden\n```\n@studio:real'), ['studio:real'])
  assert.deepEqual(referenceTokens('```\n@studio:hidden'), [])
})

test('indented code and indented fences do not emit mentions', () => {
  assert.deepEqual(referenceTokens('    @studio:hidden\n\t@studio:also-hidden\n@studio:real'), ['studio:real'])
  assert.deepEqual(referenceTokens('   ```js\n@studio:hidden\n   ```\n@studio:real'), ['studio:real'])
})

test('code masks preserve UTF-16 offsets around emoji and original query spelling', () => {
  assert.deepEqual(referenceTokens('```\n😀 @studio:hidden\n```\n😀 @"studio:研究 😀/docs.md"'), ['studio:研究 😀/docs.md'])
  assert.deepEqual(referenceTokens('`😀 @studio:hidden` @studio:研究'), ['studio:研究'])
})

test('punctuation stays in the original plain token rather than guessing a file name', () => {
  assert.deepEqual(referenceTokens('@studio:Notes, @studio:文件。'), ['studio:Notes,', 'studio:文件。'])
})

test('character budget rejects an incomplete plain or quoted token at the cut', () => {
  assert.deepEqual(extractReferenceTokens('@studio:long-name', { maxChars: 10 }), { tokens: [], truncated: true })
  assert.deepEqual(extractReferenceTokens('@"studio:long-name"', { maxChars: 10 }), { tokens: [], truncated: true })
  assert.deepEqual(extractReferenceTokens('@studio:a rest', { maxChars: 9 }), { tokens: ['studio:a'], truncated: true })
  assert.deepEqual(extractReferenceTokens('@"studio:a" rest', { maxChars: 11 }), { tokens: ['studio:a'], truncated: true })
})

test('query budget rejects instead of silently truncating and still finds later valid mentions', () => {
  assert.deepEqual(extractReferenceTokens('@studio:toolong @ok:a', { maxQueryLength: 6 }), { tokens: ['ok:a'], truncated: true })
  assert.deepEqual(extractReferenceTokens('@"studio:toolong" @ok:a', { maxQueryLength: 6 }), { tokens: ['ok:a'], truncated: true })
  assert.deepEqual(extractReferenceTokens('@123456', { maxQueryLength: 6 }), { tokens: ['123456'], truncated: false })
})

test('mention budget is over distinct complete queries and reports omitted tokens', () => {
  assert.deepEqual(extractReferenceTokens('@one @one @two @three', { maxMentions: 2 }), { tokens: ['one', 'two'], truncated: true })
  assert.deepEqual(extractReferenceTokens('@one @one @two', { maxMentions: 2 }), { tokens: ['one', 'two'], truncated: false })
  assert.deepEqual(referenceTokens('@one @two', { maxMentions: 1 }), ['one'])
})

test('default and hard budget limits prevent unbounded tokens and invalid caller configuration', () => {
  assert.deepEqual(DEFAULT_REFERENCE_TOKEN_BOUNDS, { maxChars: 65_536, maxQueryLength: 2_048, maxMentions: 20 })
  const oversized = extractReferenceTokens('@studio:' + 'x'.repeat(1_000_000))
  assert.deepEqual(oversized, { tokens: [], truncated: true })
  for (const options of [{ maxChars: 0 }, { maxChars: 1_048_577 }, { maxQueryLength: 8_193 }, { maxMentions: 101 }, { maxMentions: 1.2 }, { maxChars: NaN }, { maxQueryLength: Infinity }]) {
    assert.throws(() => extractReferenceTokens('@studio:test', options), TypeError)
  }
})

test('control characters and NUL code sentinels cannot enter a quoted or plain query', () => {
  assert.deepEqual(referenceTokens('@studio:a\u0000b @"studio:a\u007fb" @studio:real'), ['studio:real'])
})

test('many unequal backtick runs remain bounded and avoid quadratic suffix searches', () => {
  const source = Array.from({ length: 200 }, (_, index) => '`'.repeat(index + 1) + ' x ').join('') + '\n@studio:real'
  const result = extractReferenceTokens(source)
  assert.ok(result.tokens.length <= 20)
  assert.ok(result.tokens.every(token => token.length <= 2_048))
})
