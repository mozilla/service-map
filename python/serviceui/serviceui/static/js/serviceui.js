function trColor() {
  var atc = document.getElementsByName("rlabel")
  for (var i = 0, m = atc.length; i < m; i++) {
    var node = atc[i];
    if (!node.childNodes[0] || node.childNodes[0].nodeValue === "unknown") {
      node.innerHTML = "unknown";
      node.className = "riskLabel riskLabelUnknown"
      continue;
    }
    var ct = node.childNodes[0].nodeValue;
    if (ct === "maximum" || ct === "secret") {
        node.className = "riskLabel riskLabelMax"
      } else if (ct === "high" || ct === "restricted") {
        node.className = "riskLabel riskLabelHigh"
      } else if (ct === "medium" || ct === "internal" || ct === "mediumlow") {
        node.className = "riskLabel riskLabelMedium"
      } else if (ct === "low" || ct === "public") {
        node.className = "riskLabel riskLabelLow"
    }
  }
}
