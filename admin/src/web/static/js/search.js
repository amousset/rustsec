const term = new URLSearchParams(window.location.search).get("q");
var idx = lunr.Index.load(searchIndex);
// we can't use search() as it considers hyphens word separators
result = idx.query(function (q) {
  q.term(term.toLowerCase(), { fields: ["title", "aliases", "keywords", "package"] })
})

console.log(result);

displayResult = ""
result.forEach(function (item, index) {
  console.log(item, index);
  displayResult = displayResult.concat("<li><a href=/advisories/"+item.ref+".html>"+item.ref+"</a></li>")
});

document.getElementById('search-result').innerHTML = displayResult;