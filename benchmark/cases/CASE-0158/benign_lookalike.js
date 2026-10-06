var db = require("../db/DB").db;

/**
 * Same db.findKeys("pad:...*") prefix query as the pad export, but the prefix
 * is a fixed string with no pad id in it: this is the admin-only listing of
 * every pad, so returning all of them is the intended behaviour.
 */
exports.listAllPadKeys = function(callback){
  db.findKeys("pad:*", null, function(err, keys){
    callback(err, keys);
  });
};
