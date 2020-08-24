function hidePasswordData() {
  // Only attempt to hide the password data if there is some.
  if (document.getElementById("passdata")) {
    // Remove content.
    window.getSelection().empty();
    document.getElementById("content-view").innerText = "[hidden]";
    document.getElementById("content-edit").remove();

    // Make the edit link noninteractive since password data has been hidden.
    const el = document.getElementById("edit-link")
    el.removeAttribute("href");
    el.onclick = null;
  }
}

function rerollGeneratedPassword() {
  const len = parseInt(document.getElementById("pwgen-length").value);
  const charset = document.getElementById("pwgen-cs").value;
  if (isNaN(len) || charset.length === 0) {
    document.getElementById("pwgen").innerText = "n/a";
    document.getElementById("pwgen-bits").innerText = "0";
    return;
  }

  const securityBits = len * Math.log2(charset.length);
  document.getElementById("pwgen").innerText = randomString(len, charset);
  document.getElementById("pwgen-bits").innerText = securityBits.toFixed(1);
}

// randomString returns a cryptographically-strong random string of the given
// length, with characters taken from the given character set.
function randomString(len, charset) {
  let result = '';
  const g = makeGenerator(charset.length);
  while (len--) {
    result += charset.charAt(g());
  }
  return result;
}

// makeGenerator returns a generator function that returns values uniformly at
// random in the range [0, k). k must be an unsigned 32-bit number, i.e. in
// the range [0, 0xFFFFFFFF].
function makeGenerator(k) {
  const MAX_UINT32 = 0xFFFFFFFF;

  // Let N = MAX_UINT32+1 = 0x100000000. Our basic randomness primitive is to
  // generate a random number uniformly in the range [0, N). We want a number
  // uniformly in the range [0, k). The first question is if we can do this
  // without rejection sampling: we can do without rejection sampling iff N %
  // k == 0, or equivalently, (N-1) % k == k - 1.

  const r = MAX_UINT32 % k;
  if (r === k-1) {
    // The desired range [0, k) divides evenly into natural range [0, N). No
    // need for rejection sampling, just use a modulus.
    return () => nextUint32() % k;
  } else {
    // The desired range [0, k) does not divide evenly into natural range [0,
    // N). We must use rejection sampling. Our basic strategy is still to use
    // a modulus, but reject any samples from [0, N) that are in the final
    // "partial" band of remainders to ensure uniformity in the eventual
    // result. There are N % k == r + 1 elements in the partial band, so we
    // want to reject any samples values that are greater than or equal to N -
    // (N % k) == N - (r+1) == MAX_UINT32 - r.
    const lim = MAX_UINT32 - r;
    return () => {
      let v;
      do {
        v = nextUint32();
      } while (v >= lim);
      return v % k;
    };
  }
}

// nextUint32 returns a uniformly-chosen random uint32, i.e. in the range [0,
// 0xFFFFFFFF].
function nextUint32() {
  const BUF_SZ = 256;
  if (nextUint32.buf === undefined) {
    nextUint32.buf = new Uint32Array(BUF_SZ);
    nextUint32.next = BUF_SZ;
  }
  if (nextUint32.next >= BUF_SZ) {
    window.crypto.getRandomValues(nextUint32.buf);
    nextUint32.next = 0;
  }
  return nextUint32.buf[nextUint32.next++];
}

const CS_ALPHANUM = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
const CS_ALPHANUM_SPECIAL = CS_ALPHANUM + "!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~"

window.onload = function() {
  const hidePasswordDataTimeoutID = window.setTimeout(hidePasswordData, 60000);

  // General UI elements.
  const editLink = document.getElementById("edit-link")
  editLink.onclick = function() {
    // Cancel the hide-password timer since we are now in edit mode.
    window.clearTimeout(hidePasswordDataTimeoutID);

    // Set up the generated-password UI elements.
    document.getElementById("pwgen-cs").value = CS_ALPHANUM_SPECIAL;
    rerollGeneratedPassword();

    // Remove the view UI, make the edit UI visible.
    document.getElementById("content-view").remove();
    document.getElementById("content-edit").style.display = 'block';

    // Make the edit link noninteractive once it has been clicked.
    editLink.removeAttribute("href");
    editLink.onclick = null;
    return false;
  }

  // Password view UI elements.
  let copyPasswordEl = document.getElementById("copy-password");
  if (copyPasswordEl) {
    copyPasswordEl.onclick = function() {
      navigator.clipboard.writeText(document.getElementById("passdata").getAttribute("data-password"))
        .catch(err => console.error('Failed to write clipboard contents: ', err));
      return false;
    }
  }

  let showPasswordEl = document.getElementById("show-password");
  if (showPasswordEl) {
    showPasswordEl.onclick = function() {
      const password = document.getElementById("passdata").getAttribute("data-password")
      // This removes the controls, so user can't click this twice.
      document.getElementById("pass-controls").innerText = password;
      return false;
    }
  }

  // Password generator UI elements.
  document.getElementById("pwgen-copy").onclick = function() {
    const password = document.getElementById("pwgen").innerText;
    if (password === "n/a") {
      return;
    }
    navigator.clipboard.writeText(password)
      .catch(err => console.error('Failed to write clipboard contents: ', err));
  }

  document.getElementById("pwgen-reroll").onclick = rerollGeneratedPassword;
  document.getElementById("pwgen-length").onchange = rerollGeneratedPassword;
  document.getElementById("pwgen-cs").onchange = rerollGeneratedPassword;
  
  const pwgenCsEl = document.getElementById("pwgen-cs");
  document.getElementById("pwgen-cs-lns").onclick = function() {
    pwgenCsEl.disabled = true;
    if (pwgenCsEl.value !== CS_ALPHANUM_SPECIAL) {
      pwgenCsEl.value = CS_ALPHANUM_SPECIAL;
      rerollGeneratedPassword();
    }
  }
  document.getElementById("pwgen-cs-ln").onclick = function() {
    pwgenCsEl.disabled = true;
    if (pwgenCsEl.value !== CS_ALPHANUM) {
      pwgenCsEl.value = CS_ALPHANUM;
      rerollGeneratedPassword();
    }
  }
  document.getElementById("pwgen-cs-custom").onclick = function() {
    pwgenCsEl.disabled = false;
    pwgenCsEl.focus();
  }
}
