#!/usr/bin/env node
import fs from 'node:fs';

// Node won't strip types under node_modules, so the published package runs the compiled dist/
// (built on pack, deleted after). A checkout has no dist/ and runs the TypeScript directly.
const compiled = new URL('../dist/cli.js', import.meta.url);
await import(fs.existsSync(compiled) ? compiled.href : '../src/cli.ts');
