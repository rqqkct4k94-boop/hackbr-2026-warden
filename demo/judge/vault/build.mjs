import {build} from 'esbuild';
import {createHash} from 'node:crypto';
import {readFileSync, mkdirSync, writeFileSync} from 'node:fs';
import {dirname, join} from 'node:path';
import {fileURLToPath} from 'node:url';
import {assetHash, validateStorage} from './storage.mjs';

const here = dirname(fileURLToPath(import.meta.url));
const judge = dirname(here);
const read = name => readFileSync(join(judge, name), 'utf8').replaceAll('\r\n', '\n');
const json = name => JSON.parse(read(name));
const sha = text => createHash('sha256').update(text).digest('hex');
if (process.argv.length > 3) throw Error('Usage: node build.mjs [owner-public-report.json]');
const issuanceText = read('issuance-case.json');
if (sha(issuanceText) !== assetHash || sha(read('issuance-pins.json')) !==
    'c5dd1c2621db69ca6ab07203c363f2d393d29b5b9b1910617245e73af9c22a26') throw Error('PR #7 fixture or pins differ');
const data = {issuanceText, pins:json('issuance-pins.json'), pqc:json('recorded-native-pqc-proof.json'),
  pqcPins:json('recorded-native-pqc-pin.json'), cloudHead:json('recorded-cloud.json').live_acceptance.audit.head,
  storage:process.argv[2] ? validateStorage(JSON.parse(readFileSync(process.argv[2], 'utf8'))) : null};
const js = await build({absWorkingDir:here, entryPoints:['walkthrough.mjs'], bundle:true, write:false,
  platform:'browser', format:'iife', target:'es2022', legalComments:'inline', charset:'utf8'});
const htmlEscape = txt => txt.replaceAll('&','&amp;').replaceAll('<','&lt;');
const notices = ['post-quantum','hashes','curves','ciphers'].map(pkg => {
  const license = readFileSync(join(here,'node_modules','@noble',pkg,'LICENSE'),'utf8');
  return '@noble/' + pkg + '\n' + license;
}).join('\n');
const html = read('vault/page.html').replace('<!--DATA-->', () =>
  '<script type="application/json" id="evidence">' + JSON.stringify(data).replaceAll('<','\\u003c') + '</script>')
  .replace('<!--APP-->', () => '<script>' + js.outputFiles[0].text.replace(/<\/script/gi,'<\\/script') + '</script>')
  .replace('<!--LICENSES-->', () => htmlEscape(notices));
const dist = join(judge,'dist');
mkdirSync(dist,{recursive:true});
writeFileSync(join(dist,'farol-26.html'), html);
console.log('farol-26.html · SHA-256 ' + sha(html));
