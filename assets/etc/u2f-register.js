function registerCallback(resp) {
  // Check error.
  var el = document.getElementById("message");
  if (('errorCode' in resp) && (resp.errorCode !== u2f.ErrorCodes['OK'])) {
    var msg = 'U2F error ' + resp.errorCode;
    for (name in u2f.ErrorCodes) {
      if (resp.errorCode === u2f.ErrorCodes[name]) {
        msg += ' (' + name + ')';
      }
    }
    if (resp.errorMessage) {
      msg += ': ' + resp.errorMessage;
    }
    el.textContent = msg;
    return;
  }

  // POST request to server and display response.
  var xhr = new XMLHttpRequest();
  xhr.open('POST', '/register');
  xhr.setRequestHeader('Content-Type', 'application/json');
  xhr.timeout = 5000;
  xhr.addEventListener("load", function() {
    if (xhr.status === 200) {
      el.textContent = 'Registration: ' + xhr.responseText;
    } else {
      el.textContent = 'Server error: ' + xhr.statusText;
    }
  });
  xhr.send(JSON.stringify(resp));
}

var req = JSON.parse(document.getElementById("data").getAttribute("data-req"));
u2f.register(req.appId, req.registerRequests, req.registeredKeys, registerCallback);
