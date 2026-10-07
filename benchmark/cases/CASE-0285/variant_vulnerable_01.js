var SqlString = exports;

SqlString.escapeId = function (val, forbidQualified) {
  if (forbidQualified) {
    return '`' + val.replace(/`/g, '``') + '`';
  }
  return '`' + val.replace(/`/g, '``').replace(/\./g, '`.`') + '`';
};

SqlString.escape = function(value, stringifyObjects, timeZone, dialect) {
  if (value === undefined || value === null) {
    return 'NULL';
  }

  switch (typeof value) {
    case 'boolean': return (value) ? 'true' : 'false';
    case 'number': return value+'';
  }

  if (value instanceof Date) {
    value = SqlString.dateToString(value, timeZone || "Z");
  }

  if (Buffer.isBuffer(value)) {
    return SqlString.bufferToString(value);
  }

  if (Array.isArray(value)) {
    return SqlString.arrayToList(value, timeZone);
  }

  if (typeof value === 'object') {
    if (stringifyObjects) {
      value = value.toString();
    } else {
      return SqlString.objectToValues(value, timeZone);
    }
  }

  if (dialect == "postgres") {
    // http://www.postgresql.org/docs/8.2/static/sql-syntax-lexical.html#SQL-SYNTAX-STRINGS
    value = value.replace(/'/g, "''");
  } else {
    value = value.replace(/[\0\n\r\b\t\\\'\"\x1a]/g, function(ch) {
      switch(ch) {
        case "\0": return "\\0";
        case "\n": return "\\n";
        case "\r": return "\\r";
        case "\b": return "\\b";
        case "\t": return "\\t";
        case "\x1a": return "\\Z";
        default: return "\\"+ch;
      }
    });
  }
  return "'"+value+"'";
};

SqlString.arrayToList = function(array, timeZone) {
  return array.map(function(v) {
    if (Array.isArray(v)) return '(' + SqlString.arrayToList(v) + ')';
    return SqlString.escape(v, true, timeZone);
  }).join(', ');
};

SqlString.format = function(sql, values, timeZone, dialect) {
  values = [].concat(values);

  return sql.replace(/\?/g, function(match) {
    if (!values.length) {
      return match;
    }

    return SqlString.escape(values.shift(), false, timeZone, dialect);
  });
};

SqlString.dateToString = function(date, timeZone) {
  var dt = new Date(date);

  if (timeZone != 'local') {
    var tz = convertTimezone(timeZone);

    dt.setTime(dt.getTime() + (dt.getTimezoneOffset() * 60000));
    if (tz !== false) {
      dt.setTime(dt.getTime() + (tz * 60000));
    }
  }

  var year   = dt.getFullYear();
  var month  = zeroPad(dt.getMonth() + 1);
  var day    = zeroPad(dt.getDate());
  var hour   = zeroPad(dt.getHours());
  var minute = zeroPad(dt.getMinutes());
  var second = zeroPad(dt.getSeconds());

  return year + '-' + month + '-' + day + ' ' + hour + ':' + minute + ':' + second;
};

SqlString.bufferToString = function(buffer) {
  var hex = '';
  try {
    hex = buffer.toString('hex');
  } catch (err) {
    // node v0.4.x does not support hex / throws unknown encoding error
    for (var i = 0; i < buffer.length; i++) {
      var byte = buffer[i];
      hex += zeroPad(byte.toString(16));
    }
  }

  return "X'" + hex+ "'";
};

SqlString.objectToValues = function(object, timeZone) {
  var values = [];
  for (var key in object) {
    var value = object[key];
    if(typeof value === 'function') {
      continue;
    }

    values.push(this.escapeId(key) + ' = ' + SqlString.escape(value, true, timeZone));
  }

  return values.join(', ');
};

function zeroPad(number) {
  return (number < 10) ? '0' + number : number;
}

function convertTimezone(tz) {
  if (tz == "Z") return 0;

  var m = tz.match(/([\+\-\s])(\d\d):?(\d\d)?/);
  if (m) {
    return (m[1] == '-' ? -1 : 1) * (parseInt(m[2], 10) + ((m[3] ? parseInt(m[3], 10) : 0) / 60)) * 60;
  }
  return false;
}
