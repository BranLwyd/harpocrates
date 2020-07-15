async function performRegistration(challenge) {
  const el = document.getElementById("message");

  try {
    // Get a new credential based on the options included as the challenge.
    const pubKeyCredOpts = JSON.parse(challenge);
    pubKeyCredOpts.challenge = Uint8Array.from(atob(pubKeyCredOpts.challenge), c => c.charCodeAt(0));
    pubKeyCredOpts.user.id = Uint8Array.from(atob(pubKeyCredOpts.user.id), c => c.charCodeAt(0));
    const cred = await navigator.credentials.create({publicKey: pubKeyCredOpts});

    // Send the credential to the server to get the registration.
    const toSend = {
      id: cred.id,
      type: cred.type,
      rawId: btoa(String.fromCharCode.apply(null, new Uint8Array(cred.rawId))),
      response: {
        attestationObject: btoa(String.fromCharCode.apply(null, new Uint8Array(cred.response.attestationObject))),
        clientDataJSON: btoa(String.fromCharCode.apply(null, new Uint8Array(cred.response.clientDataJSON))),
      },
    }
    if(cred.extensions) {
      toSend.extensions = cred.extensions;
    }

    const resp = await fetch('/register', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify(toSend),
    });

    // Display the registration on the page.
    if (resp.ok) {
      const reg = await resp.text();
      el.innerText = `Registration: ${reg}`;
    } else {
      const errorText = await resp.text();
      throw errorText
    }
  } catch (e) {
    console.error(e);
    el.innerText = `Registration failure (see console for details)`;
  }
}

performRegistration(document.getElementById("data").getAttribute("data-challenge"));