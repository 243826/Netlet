package com.celeral.netlet.rpc.secure;

import com.celeral.netlet.codec.CipherStatefulStreamCodec;

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
    this.token = CipherStatefulStreamCodec.getRandomBytes(16);
    this.iv = CipherStatefulStreamCodec.getRandomBytes(16);
  }

  @Override
  public String getId()
  {
    return id;
  }

  @Override
  public byte[] getSecret()
  {
    return token;
  }

  @Override
  public byte[] getInitializationVector()
  {
    return iv;
  }
}
