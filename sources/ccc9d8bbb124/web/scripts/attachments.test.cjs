const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const ts = require('typescript');
const path = require('node:path');

function load(relative, imports, globals = {}) {
  const filename = path.join(__dirname, '..', relative);
  const code = ts.transpileModule(fs.readFileSync(filename, 'utf8'), {
    fileName: filename,
    compilerOptions: { module: ts.ModuleKind.CommonJS, jsx: ts.JsxEmit.ReactJSX, target: ts.ScriptTarget.ES2022 },
  }).outputText;
  const exports = {};
  vm.runInNewContext(code, { exports, require: (name) => {
    if (!(name in imports)) throw new Error(`Unexpected import ${name}`);
    return imports[name];
  }, process: {env: {}}, FormData, File, ...globals }, {filename});
  return exports;
}

function dropzone(disabled, onFiles) {
  return load('src/components/attachment-dropzone.tsx', {
    react: { useState: () => [false, () => {}], useRef: () => ({current: 0}) },
    'react/jsx-runtime': { jsx: (type, props) => ({type, props}), jsxs: (type, props) => ({type, props}) },
    '@/lib/utils': { cn: (...values) => values.filter(Boolean).join(' ') },
  }).AttachmentDropzone({disabled, onFiles}).props;
}

test('drop and paste deliver files; ordinary text paste is untouched', () => {
  const selected = [];
  const handlers = dropzone(false, (files) => selected.push(...files));
  const file = new File(['synthetic input'], 'input.txt');
  let prevented = 0;
  const event = { preventDefault: () => prevented++, dataTransfer: {types: ['Files'], files: [file]} };
  handlers.onDragEnter(event); handlers.onDragOver(event); handlers.onDrop(event);
  assert.equal(event.dataTransfer.dropEffect, 'copy');
  handlers.onPaste({preventDefault: () => prevented++, clipboardData: {files: [file]}});
  handlers.onPaste({preventDefault: () => assert.fail('text paste was intercepted'), clipboardData: {files: []}});
  assert.deepEqual(selected, [file, file]);
  assert.equal(prevented, 4);
});

test('disabled controls block file drop/paste and prevent browser navigation', () => {
  const handlers = dropzone(true, () => assert.fail('disabled upload started'));
  let prevented = 0;
  const event = {preventDefault: () => prevented++, dataTransfer: {types: ['Files'], files: [new File(['x'], 'x')]}};
  handlers.onDragOver(event); handlers.onDrop(event);
  assert.equal(event.dataTransfer.dropEffect, 'none');
  handlers.onPaste({preventDefault: () => prevented++, clipboardData: {files: event.dataTransfer.files}});
  assert.equal(prevented, 3);
});

function client(fetch) {
  return load('src/lib/api.ts', {'@/lib/mock/enabled': {MOCK: false}, '@/lib/mock/handler': {mockHandle: () => assert.fail('mock called')}}, {fetch}).api;
}

test('20 MiB applies per file; multiple attachments use separate requests', async () => {
  let requests = 0;
  const api = client(async (url, init) => {
    requests++;
    assert.equal(init.body.getAll('file').length, 1);
    const f = init.body.get('file');
    return {ok: true, json: async () => ({attachments: [{name: f.name, size: f.size, path: '/remote/temp/uploads/'+f.name}]})};
  });
  const file = new File([new Uint8Array(20*1024*1024)], 'full-size.dat');
  const result = await api.chatUpload('task', '1', [file, file]);
  assert.equal(result.attachments.length, 2);
  assert.equal(requests, 2);
});

test('oversized selections fail before sending; earlier successful uploads survive a later failure', async () => {
  let requests = 0;
  const api = client(async () => {
    requests++;
    return requests === 1 ? {ok: true, json: async () => ({attachments: [{name: 'first.txt', path: '/remote/temp/uploads/first.txt'}]})}
      : {ok: false, status: 502, json: async () => ({error: 'Executor disconnected'})};
  });
  const first = new File(['x'], 'first.txt');
  await assert.rejects(api.chatUpload('task', '1', [first, new File([new Uint8Array(20*1024*1024+1)], 'large')]), /20 MiB/);
  assert.equal(requests, 0);
  const saved = [];
  await assert.rejects(api.chatUpload('task', '1', [first, first], undefined, (files) => saved.push(...files)), /Executor disconnected/);
  assert.equal(saved.length, 1);
  assert.equal(saved[0].name, 'first.txt');
});
