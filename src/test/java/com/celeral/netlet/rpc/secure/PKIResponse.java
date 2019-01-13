package com.celeral.netlet.rpc.secure;

public  class PKIResponse implements Authenticator.Response
{
  int sessionId;
  byte[] token;

  private PKIResponse()
  {
    /* jlto */
  }

  public PKIResponse(int sessionId, byte[] token)
  {
    this.sessionId = sessionId;
    this.token = token;
  }

  @Override
  public byte[] getToken()
  {
    return token;
  }

  @Override
  public int getSessionId()
  {
    return sessionId;
  }
}

