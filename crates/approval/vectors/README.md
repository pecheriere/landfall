# Real-browser vectors

`chromium.json` holds one ES256 and one EdDSA credential from Chromium's virtual
authenticator: its attestation (`none`, as requested), and an assertion over the
challenge of the intent in the file (`DeployIntent::challenge`).
`real_browser_vectors_verify` checks them. They are what a browser actually sends,
which a test authenticator written next to the verifier can't show: its key encoding,
the extra member Chromium sometimes adds to `clientDataJSON`, the flags and the counter.

The private keys were thrown away with the virtual authenticator, so these bytes
can't sign anything else. Nothing in them is personal: the origin is
`https://landfall.example`, the user is `operator`.

## Regenerating

Any Playwright will do, with a Chromium it has installed. The page is served by
Playwright itself, so the name doesn't have to resolve and no certificate is
involved; the browser still treats it as a secure context with that origin. Run this
as a Playwright snippet, with `page` a new page:

```js
async (page) => {
  await page.route('https://landfall.example/**', (r) =>
    r.fulfill({ status: 200, contentType: 'text/html', body: '<!doctype html><title>vector</title>' }));
  await page.goto('https://landfall.example/');
  const cdp = await page.context().newCDPSession(page);
  await cdp.send('WebAuthn.enable');
  const credentials = [];
  for (const [algorithm, alg] of [['ES256', -7], ['EdDSA', -8]]) {
    const { authenticatorId } = await cdp.send('WebAuthn.addVirtualAuthenticator', {
      options: {
        protocol: 'ctap2',
        transport: 'internal',
        hasResidentKey: true,
        hasUserVerification: true,
        isUserVerified: true,
        automaticPresenceSimulation: true,
      },
    });
    const credential = await page.evaluate(async ({ alg }) => {
      const b64 = (buffer) => btoa(String.fromCharCode(...new Uint8Array(buffer)))
        .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
      const created = await navigator.credentials.create({ publicKey: {
        challenge: new Uint8Array(32).fill(0x11),
        rp: { id: 'landfall.example', name: 'landfall' },
        user: { id: new Uint8Array([1]), name: 'operator', displayName: 'operator' },
        pubKeyCredParams: [{ type: 'public-key', alg }],
        authenticatorSelection: { userVerification: 'required', residentKey: 'required' },
        attestation: 'none',
      } });
      // The challenge of the intent in chromium.json.
      const challenge = Uint8Array.from(
        '1450185144696e3becd3230aa9a78d5931a1d52155686619ba6f2f5518f60180'
          .match(/../g).map((byte) => parseInt(byte, 16)));
      const got = await navigator.credentials.get({ publicKey: {
        challenge,
        rpId: 'landfall.example',
        allowCredentials: [{ type: 'public-key', id: created.rawId }],
        userVerification: 'required',
      } });
      return {
        attestation_object: b64(created.response.attestationObject),
        registration_client_data_json: b64(created.response.clientDataJSON),
        assertion: {
          credential_id: b64(got.rawId),
          authenticator_data: b64(got.response.authenticatorData),
          client_data_json: b64(got.response.clientDataJSON),
          signature: b64(got.response.signature),
        },
      };
    }, { alg });
    credentials.push({ algorithm, ...credential });
    await cdp.send('WebAuthn.removeVirtualAuthenticator', { authenticatorId });
  }
  return JSON.stringify(credentials);
}
```

Replace `credentials` in `chromium.json` with the result, and the browser's version
in `source`.

Chromium adds the `other_keys_can_be_added_here` member to `clientDataJSON` at random,
so a regeneration can drop it. The committed assertions both have it, and
`other_members_are_allowed` covers extra members whatever a vector holds.
