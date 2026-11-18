// demo-shop's web server (B9). INTENTIONALLY VULNERABLE: each seeded weakness names its ground-truth id
// (demo-shop/ground-truth/findings.yaml). Never run it outside its container, never expose it beyond
// localhost.
//
// `node server.js` listens on port 8080 (infra/k8s/web.yaml): it serves the front end (public/), answers the
// probes on /healthz, makes product thumbnails and forwards /api/ to shop-api. Node's standard library only:
// the dependencies in package.json are seeds, and this file imports none of them.
"use strict";

const { exec } = require("node:child_process");
const fs = require("node:fs");
const http = require("node:http");
const https = require("node:https");
const path = require("node:path");

const PORT = 8080;
const SHOP_API = process.env.SHOP_API_URL || "https://shop-api.demo-shop.svc:8000";
const IMAGES = path.join(__dirname, "images");
const FILES = {
  "/": ["index.html", "text/html; charset=utf-8"],
  "/app.js": ["app.js", "text/javascript; charset=utf-8"],
};

// GT-SAST-010: the forward route calls shop-api over TLS (SHOP_API_URL) and never checks its certificate, so
// anyone on the path between the two pods can read or change the catalogue and the orders.
const shopApi = new https.Agent({ keepAlive: true, rejectUnauthorized: false });
const SHOP_API_ORIGIN = new URL(SHOP_API).origin;

function forward(request, response) {
  // Not a seed: only shop-api is reached. "/api//other.host/x" would otherwise resolve to another host.
  const target = new URL(request.url.slice("/api".length), SHOP_API_ORIGIN);
  if (target.origin !== SHOP_API_ORIGIN) {
    response.writeHead(400);
    response.end();
    return;
  }
  const type = request.headers["content-type"] || "text/plain";
  const headers = { accept: "application/json", "content-type": type };
  const upstream = https.request(target, { method: request.method, headers, agent: shopApi }, (answer) => {
    response.writeHead(answer.statusCode, { "content-type": answer.headers["content-type"] || "text/plain" });
    answer.pipe(response);
  });
  upstream.on("error", () => {
    response.writeHead(502);
    response.end();
  });
  request.pipe(upstream);
}

function thumbnail(sku, response) {
  // GT-SAST-009: the SKU from the address becomes part of a shell command.
  exec(`convert ${IMAGES}/${sku}.png -resize 160x160 png:-`, { encoding: "buffer" }, (error, image) => {
    if (error) {
      response.writeHead(404);
      response.end();
      return;
    }
    response.writeHead(200, { "content-type": "image/png", "cache-control": "max-age=3600" });
    response.end(image);
  });
}

function serve(request, response) {
  const url = new URL(request.url, "http://localhost");
  if (url.pathname === "/healthz") {
    response.writeHead(200, { "content-type": "application/json" });
    response.end(JSON.stringify({ status: "ok" }));
  } else if (url.pathname.startsWith("/api/")) {
    forward(request, response);
  } else if (url.pathname === "/thumbnail") {
    thumbnail(url.searchParams.get("sku") || "", response);
  } else if (Object.hasOwn(FILES, url.pathname)) {
    const [name, type] = FILES[url.pathname];
    response.writeHead(200, { "content-type": type });
    fs.createReadStream(path.join(__dirname, "public", name)).pipe(response);
  } else {
    response.writeHead(404);
    response.end();
  }
}

http.createServer(serve).listen(PORT, () => console.log(`web listening on port ${PORT}`));
