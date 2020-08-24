async function performAuthentication(challenge) {
  try {
    // Authenticate possession of the credential based on the server's challenge.
    const pubKeyCredOpts = JSON.parse(challenge);
    pubKeyCredOpts.challenge = Uint8Array.from(atob(pubKeyCredOpts.challenge), c => c.charCodeAt(0));
    if(pubKeyCredOpts.allowCredentials) {
      for (let i = 0; i < pubKeyCredOpts.allowCredentials.length; i++) {
        pubKeyCredOpts.allowCredentials[i].id = Uint8Array.from(atob(pubKeyCredOpts.allowCredentials[i].id), c => c.charCodeAt(0));
      }
    }
    const resp = await navigator.credentials.get({publicKey: pubKeyCredOpts});

    // POST the response back to the server.
    const toSend = {
      id: resp.id,
      rawId: btoa(String.fromCharCode.apply(null, new Uint8Array(resp.rawId))),
      response: {
        authenticatorData: btoa(String.fromCharCode.apply(null, new Uint8Array(resp.response.authenticatorData))),
        signature: btoa(String.fromCharCode.apply(null, new Uint8Array(resp.response.signature))),
        clientDataJSON: btoa(String.fromCharCode.apply(null, new Uint8Array(resp.response.clientDataJSON))),
      },
      type: resp.type
    }
    if(resp.extensions) {
      toSend.extensions = resp.extensions
    }

    const el = document.getElementById("response");
    el.value = JSON.stringify(toSend);
    el.form.submit();
  } catch(e) {
    const el = document.getElementById("message");
    console.error(e);
    el.innerText = `Authentication failure (see console for details)`;
  }
}

performAuthentication(document.getElementById("data").getAttribute("data-challenge"))
