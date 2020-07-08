function signCallback(resp) {
  // Check error.
  if (('errorCode' in resp) && (resp.errorCode !== u2f.ErrorCodes['OK'])) {
    var msgEl = document.getElementById("message");
    var msg = 'U2F error ' + resp.errorCode;
    for (name in u2f.ErrorCodes) {
      if (resp.errorCode === u2f.ErrorCodes[name]) {
        msg += ' (' + name + ')';
      }
    }
    if (resp.errorMessage) {
      msg += ': ' + resp.errorMessage;
    }
    msgEl.textContent = msg;
    return;
  }

  // POST response to server.
  var respEl = document.getElementById("response");
  respEl.value = JSON.stringify(resp);
  respEl.form.submit();
}

var req = JSON.parse(document.getElementById("data").getAttribute("data-req"));
u2f.sign(req.appId, req.challenge, req.registeredKeys, signCallback);
