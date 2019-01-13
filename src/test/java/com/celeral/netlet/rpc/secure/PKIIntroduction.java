package com.celeral.netlet.rpc.secure;

import com.esotericsoftware.kryo.serializers.FieldSerializer;
import com.esotericsoftware.kryo.serializers.JavaSerializer;

import java.security.PublicKey;

public class PKIIntroduction implements Authenticator.Introduction
{
  final String id;
  final String version;

  @FieldSerializer.Bind(JavaSerializer.class)
  final PublicKey key;

  private PKIIntroduction()
  {
    this(null, null, null);
  }

  public PKIIntroduction(String version, String id, PublicKey publicKey)
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
