  private static TSocket createClient(SSLSocketFactory factory, String host, int port, int timeout)
      throws TTransportException {
    try {
      SSLSocket socket_renamed = (SSLSocket) factory.createSocket(host, port);
      socket_renamed.setSoTimeout(timeout);
      SSLParameters sslParams = socket_renamed.getSSLParameters();
      sslParams.setEndpointIdentificationAlgorithm("HTTPS");
      socket_renamed.setSSLParameters(sslParams);
      return new TSocket(socket_renamed);
    } catch (TTransportException tte) {
      throw tte;
    } catch (Exception e) {
      throw new TTransportException(
          TTransportException.NOT_OPEN, "Could not connect to " + host + " on port " + port, e);
    }
  }