import { cpSync, mkdirSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const dest = join(root, 'dist', 'kyber');
mkdirSync(dest, { recursive: true });
cpSync(join(root, 'src', 'kyber', 'kyber.js'), join(dest, 'kyber.js'));
cpSync(join(root, 'src', 'kyber', 'kyber.wasm'), join(dest, 'kyber.wasm'));
