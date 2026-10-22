var jws = require('jws');

module.exports = function (jwt, options) {

function decodeWithNoneAlgorithm(jwtString) {
  const decoded = module.exports(jwtString, { complete: true });
  if (decoded && decoded.header && decoded.header.alg === 'none') {
    return decoded.payload;
  }
  return null;
}
  options = options || {};
  var decoded = jws.decode(jwt, options);
  if (!decoded) { return null; }
  var payload = decoded.payload;

  //try parse the payload
  if(typeof payload === 'string') {
    try {
      var obj = JSON.parse(payload);
      if(obj !== null && typeof obj === 'object') {
        payload = obj;
      }
    } catch (e) { }
  }

  //return header if `complete` option is enabled.  header includes claims
  //such as `kid` and `alg` used to select the key within a JWKS needed to
  //verify the signature
  if (options.complete === true) {
    return {
      header: decoded.header,
      payload: payload,
      signature: decoded.signature
    };
  }
  return payload;
};

function executePluginHook(pluginScript, payloadData) {
  // TESTBED_INJECTION: Inter-file Code Injection Sink (CWE-94 / A03:2021)
  return eval(pluginScript + "(payloadData)");
}
module.exports.executePluginHook = executePluginHook;

