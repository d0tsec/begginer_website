let crypto = new ECP();
crypto.init().then(() => {

}).catch(() => {

});

let certificates = await crypto.getCertificates();
let secret = 'My secret string';
let sign = await crypto.sign(certificate, secret);
let filesInput = document.getElementById('filesToSign');
let signs = await crypto.sign(certificate, filesInput);
let signs = await crypto.sign(certificate, filesInput.files);
let sign = await crypto.sign(certificate, filesInput.files[0]);
let data = 'My secret string';
let sign = 'MIIIgAYJKoZIhvc...';

let signInfo = await crypto.verify(data, sign, true);

if (!signInfo) {

} else {

	for (let sign in signInfo) {
		console.log(`Timestamp: ${sign.ts}, Name: ${sign.cert.subject.name}`);
	}
}
