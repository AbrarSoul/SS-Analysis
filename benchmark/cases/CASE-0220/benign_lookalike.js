// Standalone example of the same shape: a small XHR helper that sets only the
// content type of the body it sends and lets the browser handle framing.
function postJson(url, payload, onDone) {
	var request = new XMLHttpRequest();
	request.open('POST', url, true);
	request.setRequestHeader('Content-type', 'application/json');
	request.onreadystatechange = function () {
		if (request.readyState === 4) onDone(request.status, request.responseText);
	};
	request.send(JSON.stringify(payload));
}
