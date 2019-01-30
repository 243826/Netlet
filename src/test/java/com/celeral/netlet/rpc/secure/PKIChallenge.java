package com.celeral.netlet.rpc.secure;

import java.util.UUID;

import com.esotericsoftware.kryo.serializers.FieldSerializer;

import com.celeral.netlet.codec.CipherStatefulStreamCodec;

public class PKIChallenge implements Authenticator.Challenge
{
  @FieldSerializer.Bind(UUIDSerializer.class)
  UUID id;
  byte[] token;
  private byte[] iv;

  private PKIChallenge()
  {
    /* jlto */
  }

  public PKIChallenge(UUID id)
  {
    this.id = id;
    this.token = CipherStatefulStreamCodec.getRandomBytes(16);
    this.iv = CipherStatefulStreamCodec.getRandomBytes(16);
  }

  @Override
  public UUID getId()
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
