// demo-shop's front end, in the browser (B9). INTENTIONALLY VULNERABLE: each seeded weakness names its
// ground-truth id (demo-shop/ground-truth/findings.yaml). Served by ../server.js, which forwards /api/ to
// shop-api.
"use strict";

const params = new URLSearchParams(window.location.search);
const results = document.getElementById("results");
const total = document.getElementById("total");

function row(product) {
  const item = document.createElement("li");
  const image = document.createElement("img");
  image.src = `/thumbnail?sku=${encodeURIComponent(product.sku)}`;
  image.alt = "";
  item.append(image, `${product.name}: ${product.price.toFixed(2)} EUR`);
  return item;
}

async function search(query) {
  const answer = await fetch(`/api/products?q=${encodeURIComponent(query)}`);
  const products = await answer.json();
  if (products.length === 0) {
    // GT-SAST-007: the search text from the address is written into the page as HTML.
    results.innerHTML = `<p>No product matches <strong>${query}</strong>.</p>`;
    return;
  }
  const list = document.createElement("ul");
  list.append(...products.map(row));
  results.replaceChildren(list);
}

async function cartTotal(skus, promo) {
  const products = await Promise.all(
    skus.map((sku) => fetch(`/api/products/${encodeURIComponent(sku)}`).then((answer) => answer.json())),
  );
  const price = products.reduce((sum, product) => sum + product.price, 0);
  // GT-SAST-008: a promotion from the address, such as `price * 0.9`, runs as JavaScript.
  return eval(promo || "price");
}

document.getElementById("search").addEventListener("submit", (event) => {
  event.preventDefault();
  const query = new FormData(event.target).get("q");
  window.history.replaceState(null, "", `?q=${encodeURIComponent(query)}`);
  search(query);
});

if (params.has("q")) {
  search(params.get("q"));
}
if (params.has("cart")) {
  cartTotal(params.get("cart").split(","), params.get("promo")).then((value) => {
    total.textContent = `Total: ${Number(value).toFixed(2)} EUR`;
  });
}
