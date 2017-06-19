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
    if (ct === "maximum" || ct === "secret" || ct === "confidential secret") {
        node.className = "riskLabel riskLabelMax"
      } else if (ct === "high" || ct === "restricted" || ct === "confidential restricted") {
        node.className = "riskLabel riskLabelHigh"
      } else if (ct === "medium" || ct === "internal" || ct === "mediumlow" || ct === "confidential internal") {
        node.className = "riskLabel riskLabelMedium"
      } else if (ct === "low" || ct === "public") {
        node.className = "riskLabel riskLabelLow"
    }
  }
}

function compTableFormat(r) {
	$(r).find('td span').each(function() {
		var v = parseInt($(this).html());
		if (($(this).hasClass("compfailv")) && (v > 0)) {
			$(this).addClass("riskLabel");
			if (v > 0) {
				$(this).addClass("riskLabelHigh");
				$(this).text(v + " fail");
			}
		} else if (($(this).hasClass("comppassv")) && (v > 0)) {
			var v = parseInt($(this).html());
			$(this).addClass("riskLabel");
			if (v > 0) {
				$(this).addClass("riskLabelNone");
				$(this).text(v + " pass");
			}
		} else {
			$(this).addClass("riskLabel");
			$(this).addClass("riskLabelUnknown");
			$(this).text("None");
		}
	});
}
