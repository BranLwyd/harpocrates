function hidePasswordData() {
  // Only attempt to hide the password data if there is some.
  if (document.getElementById("passdata")) {
    // Remove content.
    window.getSelection().empty();
    document.getElementById("content-view").innerText = "[hidden]";
    document.getElementById("content-edit").remove();

    // Make the edit link noninteractive since password data has been hidden.
    var el = document.getElementById("edit-link")
    el.removeAttribute("href");
    el.onclick = null;
  }
}

window.onload = function() {
  var hidePasswordDataTimeoutID = window.setTimeout(hidePasswordData, 60000);

  var editLink = document.getElementById("edit-link")
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
}
