package com.celeral.netlet.rpc.secure;

import java.security.PublicKey;

import com.esotericsoftware.kryo.serializers.FieldSerializer;
import com.esotericsoftware.kryo.serializers.JavaSerializer;

public class BasicIntroduction implements Authenticator.Introduction
{
  final String version;
  @FieldSerializer.Bind(JavaSerializer.class)
  final PublicKey key;

  private BasicIntroduction()
  {
    this(null, null);
  }

  public BasicIntroduction(String version, PublicKey publicKey)
  {
    this.version = version;
    this.key = publicKey;
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
