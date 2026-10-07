function SessionManager(options, serializeUser) {
  if (typeof options == 'function') {
    serializeUser = options;
    options = undefined;
  }
  options = options || {};
  
  this._key = options.key || 'passport';
  this._serializeUser = serializeUser;
}

SessionManager.prototype.logIn = function(req, user, cb) {
  var self = this;
  this._serializeUser(user, req, function(err, obj) {
    if (err) {
      return cb(err);
    }
    // TODO: Error if session isn't available here.
    storeUser(req, self._key, obj);
    cb();
  });
}

function storeUser(req, key, obj) {
  if (!req.session) {
    req.session = {};
  }
  if (!req.session[key]) {
    req.session[key] = {};
  }
  req.session[key].user = obj;
}

SessionManager.prototype.logOut = function(req, cb) {
  if (req.session && req.session[this._key]) {
    delete req.session[this._key].user;
  }
  
  cb && cb();
}


module.exports = SessionManager;
