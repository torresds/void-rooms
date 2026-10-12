import { createServer } from "node:http";
import { readFile } from "node:fs/promises";
import { extname, resolve, sep } from "node:path";
import { fileURLToPath } from "node:url";

const root = resolve(fileURLToPath(new URL(".", import.meta.url)));
const contentTypes = new Map([
  [".html", "text/html; charset=utf-8"],
  [".js", "text/javascript; charset=utf-8"],
  [".wasm", "application/wasm"],
]);

createServer(async (request, response) => {
  const pathname = new URL(request.url ?? "/", "http://127.0.0.1").pathname;
  const relative = pathname === "/" ? "index.html" : decodeURIComponent(pathname.slice(1));
  const filePath = resolve(root, relative);
  if (filePath !== root && !filePath.startsWith(root + sep)) {
    response.writeHead(400).end();
    return;
  }

  try {
    const body = await readFile(filePath);
    response.writeHead(200, {
      "content-type": contentTypes.get(extname(filePath)) ?? "application/octet-stream",
      "cache-control": "no-store",
    });
    response.end(body);
  } catch {
    response.writeHead(404).end();
  }
}).listen(4173, "127.0.0.1");
