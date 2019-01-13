package com.celeral.netlet.rpc.secure;

public class PKIChallenge implements Authenticator.Challenge
{
  String id;
  byte[] token;
  private byte[] iv;

  private PKIChallenge()
  {
    /* jlto */
  }

  public PKIChallenge(String id)
  {
    this.id = id;
    this.token = SecureRPCTest.getRandomBytes(16);
    this.iv = SecureRPCTest.getRandomBytes(12);
  }

  @Override
  public String getId()
  {
    return id;
  }

  @Override
  public byte[] getToken()
  {
    return token;
  }

  @Override
  public byte[] getInitializationVector()
  {
    return iv;
  }
}
