###
  CAS strategy for Passport.js
###

_ = require 'lodash'
url   = require 'url'
path  = require 'path'
http  = require 'http'
https = require 'https'
passport = require 'passport'
xml2json = require 'xml2json'

class Strategy extends passport.Strategy

  ###
    options = {
      casServiceUrl : 'https://cas-ip/cas'
      serviceBaseUrl: 'http://localhost:3000/'
      passRequetToCallback: yes/no
      validateUri: '/cas/proxyValidate'
      pgtUrl: 'https://ip/proxyGrantingTicketCallback'
    }
  ###

  _DEFAULTS = {
    name: 'cas'
    postRedirect: no
    validateMethod: 'proxyValidate'
    casServiceUrl : ''
    serviceBaseUrl: 'http://localhost:3000/'
    passRequetToCallback: no
    pgtUrl: undefined
  }

  _RESULT = {
    success: no,
    user: null
    description: ''
    code: ''
    data: {}
  }

  _VALIDATE_URL = {
    'default' : '/validate'
    'validate': '/validate'
    'proxyvalidate'  : '/proxyValidate'
    'servicevalidate': '/serviceValidate'
  }

  _validateResponseHandler = (body)->
      result = {
        data: body
      }

      [success, user] = body.split '\n'

      result.description = success

      if success.toLowerCase() is 'yes'
        result.user = user

      _.extend {}, _RESULT, result

  _proxyValidateResponseHandler = (body)->
      result = {
        data: body
      }

      data = xml2json.toJson body, { sanitize:no, object: yes}

      data = data['cas:serviceResponse'] if data['cas:serviceResponse']?

      if data['cas:authenticationFailure']?
        error = data['cas:authenticationFailure']

        result.data = error
        result.code = error.code
        result.description = error['$t']

      if data['cas:authenticationSuccess']?
        success = data['cas:authenticationSuccess']

        result.data = success
        result.success = yes
        result.code = 'OK'
        result.user = success['cas:user']

      _.extend {}, _RESULT, result

  _VALIDATE_RESPONSE_HANDLER =
    'default' : _validateResponseHandler
    'validate': _validateResponseHandler
    'proxyvalidate'  : _proxyValidateResponseHandler
    'servicevalidate': _proxyValidateResponseHandler

  constructor: (options, verifyCallback) ->

    if typeof options is 'function'
      verify  = options
      options = {}

    @options = _.extend {}, _DEFAULTS, options

    throw new Error('CAS authentication strategy requires a verify function') unless verifyCallback

    @verifyCallback = verifyCallback

    @name   = @options.name
    @parsed = url.parse @options.casServiceUrl

    @client = http

    if @parsed.protocol is 'https:'
      @client = https

    return

  _getResponseHandler: (validateMethodName = 'default')->
    validateMethodName = validateMethodName.toLowerCase()

    if _VALIDATE_RESPONSE_HANDLER[validateMethodName]?
      return _VALIDATE_RESPONSE_HANDLER[validateMethodName]

    _VALIDATE_RESPONSE_HANDLER['default']

  _getValidateUrl: (validateMethodName = 'default')->
    validateMethodName = validateMethodName.toLowerCase()

    if _VALIDATE_URL[validateMethodName]?
      return _VALIDATE_URL[validateMethodName]

    _VALIDATE_URL['default']

  _onValidateCallback: (err, user, info) ->
    return @error err if err
    return @fail info if !user

    @success user, info

  authenticate:(req, options = {}) ->
    ticket = req.param 'ticket'

    unless ticket
      redirectURL = url.parse "#{@options.casServiceUrl}/login", yes

      service = "#{@options.serviceBaseUrl}#{req.url}"

      redirectURL.query.service = service
      redirectURL.query.method  = 'POST' if @options.postRedirect

      return @redirect(url.format(redirectURL))

    resolvedURL = url.resolve @options.serviceBaseUrl, req.url
    parsedURL   = url.parse resolvedURL, yes

    delete parsedURL.query.ticket
    delete parsedURL.search

    validateUrl  = @_getValidateUrl @options.validateMethod
    validatePath = path.normalize "#{@parsed.path}#{validateUrl}"
    validateService = url.format parsedURL

    query =
      ticket : ticket
      service: validateService

    query.pgtUrl = @options.pgtUrl if @options.pgtUrl

    get = @client.get(
      rejectUnauthorized: no
      requestCert: no
      agent: no
      host: @parsed.hostname
      port: @parsed.port
      path: url.format(
        query: query
        pathname: validatePath
      )

      headers: {
        accept: 'application/json'
      }

    , (response) =>
        body = ''

        response.setEncoding 'utf8'

        response.on 'data', (chunk) ->
          body += chunk

        response.on 'end', ()=>

          validateResult  = _RESULT
          responseHandler = @_getResponseHandler @options.validateMethod

          try
            validateResult = responseHandler body
          catch error
            validateResult.code = 'HANDLER_ERROR'
            validateResult.success = no
            validateResult.description = 'HANDLER_ERROR'

            console.log error
            response.error new Error "Error during response hander work #{error}"

          if @options.passReqToCallback
            @verifyCallback req, validateResult, @_onValidateCallback.bind(this)
          else
            @verifyCallback validateResult, @_onValidateCallback.bind(this)
    )

    get.on 'error', (error) =>
      @fail new Error(error)

    return

exports.Strategy = Strategy