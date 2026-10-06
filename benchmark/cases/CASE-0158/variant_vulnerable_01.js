/**
 * 2014 John McLear (Etherpad Foundation / McLear Ltd)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS-IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */


var async = require("async");
var db = require("../db/DB").db;
var ERR = require("async-stacktrace");

exports.getPadRaw = function(padName, finish){
  async.waterfall([
  function(next){

    // Get the Pad available content keys
    db.findKeys("pad:"+padName+"*", null, function(error,found){
      if(!error){
        next(error, found);
      }
    })
  },
  function(found, next){
    var dump = {};

    async.forEachSeries(Object.keys(found), function(key, r){

      // For each piece of info about a pad.
      db.get(found[key], function(error, record){
        dump[found[key]] = record;

        // Get the Pad Authors
        if(record.pool && record.pool.numToAttrib){
          var authorAttribs = record.pool.numToAttrib;
          async.forEachSeries(Object.keys(authorAttribs), function(k, c){
            if(authorAttribs[k][0] === "author"){
              var aid = authorAttribs[k][1];

              // Get the author info
              db.get("globalAuthor:"+aid, function(e, authorRecord){
                if(authorRecord && authorRecord.padIDs) authorRecord.padIDs = padName;
                if(!e) dump["globalAuthor:"+aid] = authorRecord;
              });

            }
            // console.log("authorsK", authors[k]);
            c(null);
          });
        }
        r(null); // finish;
      });
    }, function(error){ 
      next(error, dump);
    })
  }
  ], function(error, dump){
    finish(null, dump);
  });
}
