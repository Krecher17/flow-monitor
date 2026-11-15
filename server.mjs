import {createServer} from 'node:http';
import {readFile} from 'node:fs/promises';

const files = new Map([
  ['/', ['index.html', 'text/html']],
  ['/style.css', ['style.css', 'text/css']],
  ...['dashboard', 'demo', 'detector'].map(name => [
    `/${name}.mjs`, [`${name}.mjs`, 'text/javascript']
  ])
]);
const port = process.env.PORT ? Number(process.env.PORT) : 4173;
const headers = {
  'Content-Security-Policy': "default-src 'self'; connect-src 'none'; object-src 'none'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'",
  'X-Content-Type-Options': 'nosniff'
};

createServer(async (request, response) => {
  const entry = files.get(request.url.split('?')[0]);
  if (request.method !== 'GET' || !entry) {
    response.writeHead(404, headers).end();
    return;
  }
  const [file, mime] = entry;
  try {
    const body = await readFile(new URL(file, import.meta.url));
    response.writeHead(200, {...headers, 'Content-Type': `${mime}; charset=utf-8`}).end(body);
  } catch {
    response.writeHead(500, headers).end('Could not load dashboard asset.');
  }
}).listen(port, '127.0.0.1', () => console.log(`Dashboard at http://127.0.0.1:${port}`));
