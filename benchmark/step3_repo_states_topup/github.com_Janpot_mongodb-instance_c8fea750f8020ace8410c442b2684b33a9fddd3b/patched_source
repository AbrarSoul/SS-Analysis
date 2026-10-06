'use strict';

var util = require('util'),
    path = require('path'),
    http = require('http'),
    tar  = require('tar'),
    zlib = require('zlib');



var platformPart = null,
    extension    = 'tgz',
    versionPart  = '2.4.9';

if (process.platform === 'linux' && process.arch === 'x64') {
  platformPart = 'linux-x86_64';
} else if (process.platform === 'linux') {
  platformPart = 'linux-i686';
} else if (
  process.platform === 'darwin' ||
  process.platform === 'openbsd' ||
  process.platform === 'freebsd'
) {
  platformPart = 'osx-x86_64';
} else if (process.platform === 'win32') {
  console.log('Windows not supported');
  process.exit(1);
} else {
  console.log(
    'Unexpected platform or architecture: %s - %s',
    process.platform,
    process.arch
  );
  process.exit(1);
}



var downloadUrl = util.format(
  'https://fastdl.mongodb.org/osx/mongodb-%s-%s.%s',
  platformPart,
  versionPart,
  extension
);

var downloadFolder = path.join(__dirname, 'bin/mongo');


function extract(stream) {
  stream
    .pipe(zlib.Unzip())
    .on('error', function (er) {
      console.error('zlib error: ' + er.message);
    })
    .pipe(tar.Extract({
      path: downloadFolder,
      strip: 1
    }))
    .on('error', function (er) {
      console.error('tar error: ' + er.message);
    })
    .on('entry', function (entry) {
      console.error('extracting: ' + entry.path);
    })
    .on('end', function () {
      console.error('done');
    });
}

function download() {
  http.get(downloadUrl, extract).on('error', function (e) {
    console.log('Got error: ' + e.message);
  });
}

download();
