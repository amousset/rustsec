outputDir = "_site/js/"
const fs = require('fs');
var lunr = require('lunr');

let data = fs.readFileSync(outputDir + '/index.json','utf-8');
let docs = JSON.parse(data);

let idx = lunr(function () {
	this.ref('ident');
	this.field('title');
	this.field('aliases');
	this.field('keywords');
	this.field('package');

	docs.forEach(function (doc, idx) {
		doc.id = idx;
		this.add(doc);
	}, this);
});

fs.writeFileSync(outputDir + 'lunr-index.js', 'var searchIndex = '+JSON.stringify(idx))+';';

