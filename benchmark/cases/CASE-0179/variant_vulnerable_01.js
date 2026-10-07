function SessionManager(options, serializeUser) {
  if (typeof options == 'function') {
    serializeUser = options;
    options = undefined;
  }
  options = options || {};
  
  this._key = options.key || 'passport';
  this._serializeUser = serializeUser;
}

SessionManager.prototype.logIn = function(request, account, done) {
  var manager = this;
  this._serializeUser(account, request, function(error, serialized) {
    if (error) {
      return done(error);
    }
    // TODO: Error if session isn't available here.
    if (!request.session) {
      request.session = {};
    }
    if (!request.session[manager._key]) {
      request.session[manager._key] = {};
    }
    request.session[manager._key].user = serialized;
    done();
  });
}

SessionManager.prototype.logOut = function(req, cb) {
  if (req.session && req.session[this._key]) {
    delete req.session[this._key].user;
  }
  
  cb && cb();
}


module.exports = SessionManager;
