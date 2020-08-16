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

window.onload = function() {
  const hidePasswordDataTimeoutID = window.setTimeout(hidePasswordData, 60000);

  const editLink = document.getElementById("edit-link")
  editLink.onclick = function() {
    // Cancel the hide-password timer since we are now in edit mode.
    window.clearTimeout(hidePasswordDataTimeoutID);

    // Remove the view UI, make the edit UI visible.
    document.getElementById("content-view").remove();
    document.getElementById("content-edit").style.display = 'block';

    // Make the edit link noninteractive once it has been clicked.
    editLink.removeAttribute("href");
    editLink.onclick = null;
    return false;
  }

  const copyLink = document.getElementById("copy-password")
  copyLink.onclick = function() {
    const el = document.getElementById("passdata")
    const password = el.getAttribute("data-password")
    navigator.clipboard.writeText(password)
      .catch(err => {
        console.error('Failed to write clipboard contents: ', err);
      });
    return false;
  }

  const showLink = document.getElementById("show-password")
  showLink.onclick = function() {
    const password = document.getElementById("passdata").getAttribute("data-password")
    // This removes the controls, so user can't click this twice.
    document.getElementById("pass-controls").innerText = password;
    return false;
  }
}
