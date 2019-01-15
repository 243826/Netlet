package com.celeral.netlet.rpc.secure;

public  class PKIResponse implements Authenticator.Response
{
  int sessionId;
  byte[] secret;

  private PKIResponse()
  {
    /* jlto */
  }

  public PKIResponse(int sessionId, byte[] secret)
  {
    this.sessionId = sessionId;
    this.secret = secret;
  }

  @Override
  public byte[] getSecret()
  {
    return secret;
  }

  @Override
  public int getSessionId()
  {
    return sessionId;
  }
}

