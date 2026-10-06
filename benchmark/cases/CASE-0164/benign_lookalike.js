"use strict";

/**
 * Same "read a query parameter" shape as getValue, but it is deliberately
 * multi-valued: a repeated parameter is expected (a multi-select filter), the
 * result is ALWAYS an array of strings, and each element is checked against
 * an allow-list, so there is no scalar-versus-array confusion.
 */
function getAllowedList(req, keyName, allowed) {
  var raw = req.query && req.query[keyName];
  var list = raw === undefined ? [] : [].concat(raw);
  return list.filter(function (item) {
    return typeof item === "string" && allowed.indexOf(item) !== -1;
  });
}

exports.getAllowedList = getAllowedList;
