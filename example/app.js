var express = require('express');
var path = require('path');
var favicon = require('static-favicon');
var logger  = require('morgan');
var cookieParser = require('cookie-parser');
var bodyParser = require('body-parser');
var session    = require('express-session');

var routes = require('./routes/index');
var users  = require('./routes/users');

var passport = require('passport');
var CasStrategy = require('passport-cas-strategy').Strategy;

passport.use(new CasStrategy({
    postRedirect  : true,
    casServiceUrl : 'https://172.17.1.36:18443/cas', // "https://10.49.128.21:8443/cas/login"
    serviceBaseUrl: 'http://localhost:3000',
    validateMethod: 'serviceValidate', // ['validate', 'proxyValidate', 'serviceValidate']
    passReqToCallback: true,
    pgtUrl: 'https://172.17.1.36:18443/yukon-security-cas-pgt-web/proxyGrantingTicketCallback'
  }, function(req, data, done) {
    var user = {'email': data.user};
    console.log(user);
    return done(null, user, data);
  }
));

var app = express();

// view engine setup
app.set('views', path.join(__dirname, 'views'));
app.set('view engine', 'jade');

app.use(favicon());
app.use(logger('dev'));
app.use(bodyParser.json());
app.use(bodyParser.urlencoded());
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public')));
app.use(session({secret: '1234567890QWERTY'}));

var users = {};
passport.serializeUser(function(user, done) {
  users[user.id] = user;
  done(null, user);
});

passport.deserializeUser(function(user, done) {
  done(null, users[user.id]);
});

app.use(passport.initialize());
app.use(passport.session());

app.get('/login', passport.authenticate('cas',  { successRedirect: '/',
  failureRedirect: '/login' }));

app.post('/login', passport.authenticate('cas', { successRedirect: '/',
  failureRedirect: '/login' }));


app.get('/', function(req, res) {
  res.send('HOME PAGE:' + req.user.email);
});

/// catch 404 and forward to error handler
app.use(function(req, res, next) {
    var err = new Error('Not Found');
    err.status = 404;
    next(err);
});

// error handlers

// development error handler
// will print stacktrace
if (app.get('env') === 'development') {
    app.use(function(err, req, res, next) {
        res.status(err.status || 500);
        res.render('error', {
            message: err.message,
            error: err
        });
    });
}

// production error handler
// no stacktraces leaked to user
app.use(function(err, req, res, next) {
    res.status(err.status || 500);
    res.render('error', {
        message: err.message,
        error: {}
    });
});

module.exports = app;