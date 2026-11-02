// The pages in a real browser, under their real headers, with Chromium's virtual authenticator:
// registration, sign-in, cancelling, approving and sign-out. `main.rs` runs this, and answers on
// stdin once it has put what the page showed into the configuration and restarted the controller.
//
// The origin has to be https, so a small proxy in here terminates TLS on a throwaway certificate
// and passes everything to the controller, as a reverse proxy would.

import { execFileSync } from "node:child_process";
import { mkdtempSync, readFileSync } from "node:fs";
import http from "node:http";
import https from "node:https";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createInterface } from "node:readline";

import { chromium } from "playwright";

const { LANDFALL_INVITE_LINK, LANDFALL_BACKEND_PORT, LANDFALL_PROXY_PORT, LANDFALL_BROWSER_CHANNEL } =
  process.env;

function certificate() {
  const dir = mkdtempSync(join(tmpdir(), "landfall-browser-"));
  const key = join(dir, "key.pem");
  const cert = join(dir, "cert.pem");
  execFileSync(
    "openssl",
    [
      "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1", "-nodes",
      "-keyout", key, "-out", cert, "-days", "1", "-subj", "/CN=localhost",
      "-addext", "subjectAltName=DNS:localhost",
    ],
    { stdio: "ignore" },
  );
  return { key: readFileSync(key), cert: readFileSync(cert) };
}

function startProxy() {
  const server = https.createServer(certificate(), (request, response) => {
    const upstream = http.request(
      {
        host: "127.0.0.1",
        port: LANDFALL_BACKEND_PORT,
        method: request.method,
        path: request.url,
        headers: request.headers,
      },
      (answer) => {
        response.writeHead(answer.statusCode, answer.headers);
        answer.pipe(response);
      },
    );
    upstream.on("error", () => {
      response.writeHead(502);
      response.end();
    });
    request.pipe(upstream);
  });
  return new Promise((resolve) => server.listen(LANDFALL_PROXY_PORT, "127.0.0.1", () => resolve(server)));
}

function check(condition, what) {
  if (!condition) {
    throw new Error(`failed: ${what}`);
  }
  console.error(`ok: ${what}`);
}

const lines = createInterface({ input: process.stdin })[Symbol.asyncIterator]();

const proxy = await startProxy();
const browser = await chromium.launch({ channel: LANDFALL_BROWSER_CHANNEL || undefined });
const context = await browser.newContext({ ignoreHTTPSErrors: true });
const page = await context.newPage();

const problems = [];
page.on("pageerror", (error) => problems.push(`page error: ${error.message}`));
page.on("console", (message) => {
  // A deliberately refused 4xx is logged by the browser as a failed load, and isn't a problem.
  if (message.type() === "error" && !message.text().includes("Failed to load resource")) {
    problems.push(`console: ${message.text()}`);
  }
});

const cdp = await context.newCDPSession(page);
await cdp.send("WebAuthn.enable");
const { authenticatorId } = await cdp.send("WebAuthn.addVirtualAuthenticator", {
  options: {
    protocol: "ctap2",
    transport: "internal",
    hasResidentKey: true,
    hasUserVerification: true,
    isUserVerified: true,
    automaticPresenceSimulation: true,
  },
});

try {
  // Registration: the code leaves the address bar, and the key is shown.
  await page.goto(LANDFALL_INVITE_LINK);
  check(new URL(page.url()).hash === "", "the code is out of the address bar");
  await page.click("#register");
  await page.waitForSelector("#result:not([hidden])");
  const fingerprint = await page.textContent("#fingerprint");
  const configLine = await page.textContent("#config-line");
  check(fingerprint.length > 0, "the fingerprint is shown");
  check(configLine.startsWith("alice = {"), "the line for the configuration is shown");
  check(
    (await page.textContent("#status")).includes("used up"),
    "the page says the link is used up",
  );
  const stored = await cdp.send("WebAuthn.getCredentials", { authenticatorId });
  check(stored.credentials.length === 1, "the authenticator holds one credential");
  check(stored.credentials[0].isResidentCredential, "it is discoverable");

  // The controller restarts with the key in its configuration.
  console.log(`REGISTERED ${configLine}`);
  await lines.next();

  // No session: the approvals page sends you to sign in.
  const origin = new URL(LANDFALL_INVITE_LINK).origin;
  await page.goto(`${origin}/approvals`);
  await page.waitForURL("**/sign-in");
  check(true, "the approvals page sends someone with no session to sign in");

  // The policy is really on: an inline script added now doesn't run.
  const blocked = await page.evaluate(() => {
    const script = document.createElement("script");
    script.textContent = "window.injected = true;";
    document.head.append(script);
    return window.injected === undefined;
  });
  check(blocked, "the policy stops an inline script");
  // That was a test of the policy, and its refusal isn't a problem with the page.
  problems.length = 0;

  let signInBody = null;
  page.on("request", (request) => {
    if (request.url().endsWith("/sign-in/finish")) {
      signInBody = request.postData();
    }
  });
  await page.click("#sign-in");
  await page.waitForURL("**/approvals");
  const cookies = await context.cookies();
  const session = cookies.find((cookie) => cookie.name === "__Host-landfall-session");
  check(session !== undefined, "the session cookie is set");
  check(session.httpOnly && session.secure && session.sameSite === "Strict", "with its attributes");
  check(
    await page.evaluate(() => !document.cookie.includes("landfall")),
    "and the page's script can't read it",
  );
  await page.waitForFunction(() =>
    document.getElementById("status").textContent.includes("Nothing is waiting"),
  );

  // What goes to the server is exactly the four assertion fields.
  const assertionFields = JSON.parse(signInBody).assertion;
  check(
    Object.keys(assertionFields).sort().join() ===
      "authenticator_data,client_data_json,credential_id,signature",
    "a sign-in sends exactly the four assertion fields",
  );

  // A lying or broken controller's text stays text: a tag, a name and a reason, on each page.
  const hostile = '<img src=x onerror="window.injected = true">';
  const noMarkup = () =>
    page.evaluate(() => document.querySelector("img") === null && window.injected === undefined);
  await page.route("**/api/v1/approvals", (route) =>
    route.fulfill({
      status: 200,
      contentType: "application/json",
      body: JSON.stringify({
        approvals: [
          {
            id: 1,
            host: hostile,
            intent: {
              deployment: hostile,
              tag: hostile,
              commit: hostile,
              digest: hostile,
              expected_running: hostile,
              nonce: hostile,
            },
            challenge: "AAAA",
            state: "awaiting_approval",
            requested_by: hostile,
            created_at: 0,
            expires_at: 0,
            can_approve: true,
          },
        ],
      }),
    }),
  );
  await page.route("**/api/v1/approvals/1/cancel", (route) =>
    route.fulfill({
      status: 403,
      contentType: "application/problem+json",
      body: JSON.stringify({ code: "forbidden", title: hostile, status: 403 }),
    }),
  );
  await page.reload();
  await page.waitForSelector("section");
  check((await page.textContent("#approvals")).includes(hostile), "a hostile tag is shown as text");
  check(await noMarkup(), "and it made no element");
  await page.getByRole("button", { name: "Cancel this request" }).click();
  await page.waitForFunction(
    (text) => document.getElementById("status").textContent === text,
    hostile,
  );
  check(await noMarkup(), "a hostile reason is shown as text, and made no element");
  await page.unroute("**/api/v1/approvals");
  await page.unroute("**/api/v1/approvals/1/cancel");

  await page.route("**/passkeys/register/begin", (route) =>
    route.fulfill({
      status: 200,
      contentType: "application/json",
      body: JSON.stringify({ principal: hostile, publicKey: {} }),
    }),
  );
  await page.goto(`${origin}/passkeys/register#code`);
  await page.click("#register");
  await page.waitForSelector("#who:not([hidden])");
  check((await page.textContent("#who")).includes(hostile), "a hostile name is shown as text");
  check(await noMarkup(), "and it made no element");
  await page.unroute("**/passkeys/register/begin");
  await page.goto(`${origin}/approvals`);
  await page.waitForFunction(() =>
    document.getElementById("status").textContent.includes("Nothing is waiting"),
  );

  const ask = () =>
    page.evaluate(async () => {
      const answer = await fetch("/api/v1/deployments/app/prod/requests", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ tag: "v1.1.0" }),
      });
      return answer.status;
    });

  // A request shows its intent's fields, and can be cancelled.
  check((await ask()) === 201, "a request can be made from the session");
  await page.reload();
  await page.waitForSelector("section");
  const shown = await page.textContent("#approvals");
  check(shown.includes("app/prod"), "the page shows the deployment");
  check(shown.includes("v1.1.0"), "the page shows the tag");
  check(shown.includes("1".repeat(40)), "the page shows the commit");
  check(shown.includes(`sha256:${"1".repeat(64)}`), "the page shows the digest");
  check(shown.includes(`sha256:${"0".repeat(64)}`), "the page shows what must be running");
  await page.getByRole("button", { name: "Cancel this request" }).click();
  await page.waitForFunction(() => document.querySelector("#approvals section") === null);
  check(true, "cancelling takes it off the page");

  // Approving takes a fresh assertion.
  check((await ask()) === 201, "another request can be made");
  await page.reload();
  await page.getByRole("button", { name: "Approve with passkey" }).click();
  await page.waitForFunction(() =>
    document.getElementById("status").textContent.includes("Approved"),
  );
  check(await page.evaluate(() => document.querySelector("#approvals section") === null), "approving takes it off the page");

  // Signing out ends it, on the server too.
  const before = (await context.cookies()).find((c) => c.name === session.name);
  await page.click("#sign-out");
  await page.waitForURL("**/sign-in");
  check(
    (await context.cookies()).every((c) => c.name !== session.name),
    "signing out clears the cookie",
  );
  await context.addCookies([before]);
  const replayed = await page.evaluate(async () => (await fetch("/api/v1/approvals")).status);
  check(replayed === 401, "the old cookie gets nothing");

  check(problems.length === 0, `no script or policy errors: ${problems.join("; ")}`);
  console.log("DONE");
} finally {
  await browser.close();
  proxy.closeAllConnections();
  proxy.close();
}
process.exit(0);
