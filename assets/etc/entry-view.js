function hidePasswordData() {
  window.getSelection().empty();
  document.getElementById("passdata").innerText = "[hidden]";
}

window.setTimeout(hidePasswordData, 60000);
