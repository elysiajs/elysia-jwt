if ('Bun' in globalThis) {
  throw new Error('❌ Use Node.js to run this test!');
}

import { jwt } from '@elysiajs/jwt';

if (typeof jwt !== 'function') {
  throw new Error('❌ ESM Node.js failed');
}

console.log('✅ ESM Node.js works!');
