const {test} = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const ts = require('typescript');
const path = require('node:path');

const filename = path.join(__dirname, '../src/lib/token-usage.ts');
const source = ts.transpileModule(fs.readFileSync(filename, 'utf8'), {
  fileName: filename, compilerOptions: {module: ts.ModuleKind.CommonJS, target: ts.ScriptTarget.ES2022},
}).outputText;
const exported = {};
vm.runInNewContext(source, {exports: exported});
const {summarizeTokenUsage} = exported;
const rows = [
  {profile_name: 'current', date: '2026-11-11', input_tokens: 100, output_tokens: 10, cache_read_tokens: 80},
  {profile_name: 'current', date: '2026-11-10', input_tokens: 50, output_tokens: 5, cache_read_tokens: 20},
  {profile_name: 'renamed historical profile', date: '2026-11-10', input_tokens: 300, output_tokens: 30, cache_read_tokens: 200},
];

test('total and stacked chart agree without counting cache twice', () => {
  const view = summarizeTokenUsage(rows, null);
  assert.equal(view.total.input + view.total.output, 495);
  assert.equal(view.total.cacheRead, 300);
  assert.equal(view.daily.reduce((sum, row) => sum + row.input + row.output + row.cacheRead, 0), 495);
  assert.equal(view.daily[0].date, '2026-11-10');
});

test('historical profile names are kept separate from the current default', () => {
  const current = summarizeTokenUsage(rows, 'current');
  const historical = summarizeTokenUsage(rows, 'renamed historical profile');
  assert.equal(current.total.input, 150);
  assert.equal(historical.total.input, 300);
  assert.equal(summarizeTokenUsage(rows, 'missing').total.input, 0);
});

test('totals use only returned period rows and a valid empty period is zero', () => {
  assert.equal(summarizeTokenUsage(rows.slice(0, 1), null).total.input, 100);
  assert.equal(summarizeTokenUsage([], null).total.input, 0);
  assert.equal(summarizeTokenUsage([], null).daily.length, 0);
});
