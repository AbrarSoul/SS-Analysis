// Standalone example of the same shape: a plugin-level constant that is only
// READ by every document (a default page label) and never written per document.
(function(API) {
  var DEFAULT_LABEL = "Page";
  API.pageLabel = function(n) {
    return DEFAULT_LABEL + " " + n;
  };
})(typeof jsPDF !== "undefined" ? jsPDF.API : {});
