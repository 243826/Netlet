package com.celeral.netlet.rpc.secure;

import java.security.PublicKey;

public class BasicIntroduction implements Authenticator.Introduction
{
  final String id;
  final String version;
  final PublicKey key;

  private BasicIntroduction()
  {
    this(null, null, null);
  }

  public BasicIntroduction(String version, String id, PublicKey publicKey)
  {
    this.version = version;
    this.id = id;
    this.key = publicKey;
  }

  @Override
  public String getId()
  {
    return id;
  }

  @Override
  public String getVersion()
  {
    return version;
  }

  @Override
  public PublicKey getKey()
  {
    return key;
  }
}
