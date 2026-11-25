import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import test from 'node:test';
import ts from 'typescript';

async function load(relative){const source=await readFile(new URL(relative,import.meta.url),'utf8');const {outputText}=ts.transpileModule(source,{compilerOptions:{target:ts.ScriptTarget.ES2022,module:ts.ModuleKind.ES2022}});return import(`data:text/javascript;base64,${Buffer.from(outputText).toString('base64')}`);}

test('outline matches source offsets, skips fenced content and keeps duplicate titles distinct',async()=>{
  const {reportOutline}=await load('../src/lib/report-outline.ts');
  const text='# Report\n\n````md\n# hidden\n```\n# still hidden\n````\n\n## Finding\n## Finding\n';
  const result=reportOutline(text);
  assert.deepEqual(result.map(x=>x.title),['Report','Finding','Finding']);
  for(const heading of result)assert.equal(text.slice(Number(heading.id.split('-').at(-1)))[0],'#');
  assert.notEqual(result[1].id,result[2].id);
});

test('UI event buffer preserves order, bounds bursts and disposes on account/task navigation',async()=>{
  const {createEventBuffer}=await load('../src/lib/event-buffer.ts');
  const batches=[];const queue=createEventBuffer(events=>batches.push(events),20);
  queue.push(1);queue.push(2);assert.equal(batches.length,0);queue.flush();assert.deepEqual(batches,[[1,2]]);
  for(let i=0;i<100;i++)queue.push(i);assert.equal(batches[1].length,100);
  queue.push('old-account');queue.dispose();await new Promise(resolve=>setTimeout(resolve,40));assert.equal(batches.length,2);
});

test('reconnected activity is merged by persisted sequence without double-counting',async()=>{
  const {mergeActivities}=await load('../src/lib/activity-merge.ts');
  const old=[{seq:1,summary:'first'},{seq:2,summary:'partial'}];
  const result=mergeActivities(old,[{seq:3,summary:'last'},{seq:2,summary:'persisted'}]);
  assert.deepEqual(result.map(x=>x.seq),[1,2,3]);assert.equal(result[1].summary,'persisted');assert.equal(old[1].summary,'partial');
});
