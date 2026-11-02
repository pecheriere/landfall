// The ceremonies, under a strict content security policy: no inline code, and whatever comes
// from the API reaches the page as text, by textContent and nothing else.
"use strict";

(function () {
  function element(id) {
    return document.getElementById(id);
  }

  function say(text) {
    element("status").textContent = text;
  }

  function fromBase64url(text) {
    const padded = text.replace(/-/g, "+").replace(/_/g, "/");
    const binary = atob(padded + "=".repeat((4 - (padded.length % 4)) % 4));
    return Uint8Array.from(binary, function (c) {
      return c.charCodeAt(0);
    });
  }

  function toBase64url(buffer) {
    const bytes = new Uint8Array(buffer);
    let binary = "";
    for (const byte of bytes) {
      binary += String.fromCharCode(byte);
    }
    return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  }

  // A POST with a JSON body. Gives the answer's JSON, or throws with the problem's own words.
  async function post(path, body) {
    const answer = await fetch(path, {
      method: "POST",
      credentials: "same-origin",
      redirect: "error",
      cache: "no-store",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    });
    return read(answer);
  }

  async function read(answer) {
    const text = await answer.text();
    const parsed = text === "" ? null : JSON.parse(text);
    if (!answer.ok) {
      const problem = new Error(parsed && parsed.title ? parsed.title : "the request failed");
      problem.status = answer.status;
      throw problem;
    }
    return parsed;
  }

  // The words for a failure, with a cancelled dialog in plain terms.
  function explain(error) {
    if (error.name === "NotAllowedError") {
      return "The passkey request was cancelled or timed out. Try again.";
    }
    return error.message;
  }

  // Runs one ceremony from a button: one at a time, saying what happened.
  function onClick(button, work) {
    button.addEventListener("click", async function () {
      button.disabled = true;
      say("");
      try {
        await work();
      } catch (error) {
        say(explain(error));
      } finally {
        button.disabled = false;
      }
    });
  }

  // The four fields of an assertion, as the API takes them, and no others.
  function assertionText(credential) {
    return {
      credential_id: toBase64url(credential.rawId),
      authenticator_data: toBase64url(credential.response.authenticatorData),
      client_data_json: toBase64url(credential.response.clientDataJSON),
      signature: toBase64url(credential.response.signature),
    };
  }

  // Signs `challenge` with whichever passkey the person picks for this site.
  function signChallenge(challenge, timeout) {
    return navigator.credentials.get({
      publicKey: {
        challenge: fromBase64url(challenge),
        userVerification: "required",
        allowCredentials: [],
        timeout: timeout,
      },
    });
  }

  function registerPage() {
    // The code is in the fragment so that it reaches no server's log. It comes out of the
    // address bar and the history as soon as it is read.
    const code = location.hash.slice(1);
    history.replaceState(null, "", location.pathname);
    const button = element("register");
    if (code === "") {
      button.disabled = true;
      say("This link has no code in it. Ask for a new one.");
      return;
    }
    onClick(button, async function () {
      const options = await post("/passkeys/register/begin", { code: code });
      const who = element("who");
      who.textContent = "Registering a passkey for " + options.principal + ".";
      who.hidden = false;
      const publicKey = options.publicKey;
      const credential = await navigator.credentials.create({
        publicKey: Object.assign({}, publicKey, {
          challenge: fromBase64url(publicKey.challenge),
          user: Object.assign({}, publicKey.user, { id: fromBase64url(publicKey.user.id) }),
        }),
      });
      const shown = await post("/passkeys/register/finish", {
        code: code,
        attestation_object: toBase64url(credential.response.attestationObject),
        client_data_json: toBase64url(credential.response.clientDataJSON),
      });
      element("principal").textContent = shown.principal;
      element("algorithm").textContent = shown.algorithm;
      element("credential-id").textContent = shown.credential_id;
      element("public-key").textContent = shown.public_key;
      element("fingerprint").textContent = shown.fingerprint;
      element("config-line").textContent = shown.config_line;
      element("result").hidden = false;
      button.hidden = true;
      say("Registered. This link is used up.");
    });
  }

  function signInPage() {
    onClick(element("sign-in"), async function () {
      const options = await post("/sign-in/begin", {});
      const credential = await signChallenge(options.publicKey.challenge, options.publicKey.timeout);
      await post("/sign-in/finish", {
        challenge: options.publicKey.challenge,
        assertion: assertionText(credential),
      });
      location.assign("/approvals");
    });
  }

  function field(list, name, value) {
    const term = document.createElement("dt");
    term.textContent = name;
    const detail = document.createElement("dd");
    detail.textContent = value;
    list.append(term, detail);
  }

  function when(seconds) {
    return new Date(seconds * 1000).toISOString();
  }

  // One request, with the intent's fields, which are what a tap signs.
  function requestCard(request) {
    const card = document.createElement("section");
    const title = document.createElement("h2");
    title.textContent = request.intent.deployment + " to " + request.intent.tag;
    const list = document.createElement("dl");
    field(list, "Deployment", request.intent.deployment);
    field(list, "Host", request.host);
    field(list, "Tag", request.intent.tag);
    field(list, "Commit", request.intent.commit);
    field(list, "Image digest", request.intent.digest);
    field(list, "Must be running now", request.intent.expected_running || "nothing: a first deploy");
    field(list, "Nonce", request.intent.nonce);
    field(list, "Challenge to sign", request.challenge);
    field(list, "Asked for by", request.requested_by);
    field(list, "Expires", when(request.expires_at));
    card.append(title, list);

    if (request.can_approve) {
      const approve = document.createElement("button");
      approve.type = "button";
      approve.textContent = "Approve with passkey";
      onClick(approve, async function () {
        const credential = await signChallenge(request.challenge, 300000);
        const done = await post("/api/v1/approvals/" + request.id, {
          assertion: assertionText(credential),
        });
        await listRequests();
        say("Approved: deploy " + done.deploy_id + " is queued. Its host checks it again.");
      });
      card.append(approve);
    }
    if (request.can_cancel) {
      const cancel = document.createElement("button");
      cancel.type = "button";
      cancel.textContent = "Cancel this request";
      onClick(cancel, async function () {
        await post("/api/v1/approvals/" + request.id + "/cancel", {});
        await listRequests();
        say("Cancelled.");
      });
      card.append(cancel);
    }
    return card;
  }

  async function listRequests() {
    const answer = await fetch("/api/v1/approvals", {
      credentials: "same-origin",
      redirect: "error",
      cache: "no-store",
    });
    if (answer.status === 401) {
      location.assign("/sign-in");
      return;
    }
    const listed = await read(answer);
    const cards = listed.approvals.map(requestCard);
    element("approvals").replaceChildren(...cards);
    if (cards.length === 0) {
      say("Nothing is waiting.");
    }
  }

  function approvalsPage() {
    onClick(element("sign-out"), async function () {
      await post("/sign-out", {});
      location.assign("/sign-in");
    });
    listRequests().catch(function (error) {
      say(explain(error));
    });
  }

  const pages = { register: registerPage, "sign-in": signInPage, approvals: approvalsPage };
  const page = pages[document.body.dataset.page];
  if (page) {
    page();
  }
})();
