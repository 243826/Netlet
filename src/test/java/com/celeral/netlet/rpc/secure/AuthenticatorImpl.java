package com.celeral.netlet.rpc.secure;

import java.io.IOException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.cert.CertificateException;
import java.util.HashMap;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.validation.constraints.NotNull;

import com.celeral.utils.Throwables;

import com.celeral.netlet.codec.CipherStatefulStreamCodec;
import com.celeral.netlet.codec.StatefulStreamCodec;
import com.celeral.netlet.rpc.ContextAware;

public class AuthenticatorImpl implements Authenticator
{
  private static final char[] PASSWORD = "Test123".toCharArray();

  HashMap<String, PublicKey> publicKeys = new HashMap<>();

  KeyStore keystore;
  KeyPair master;

  public AuthenticatorImpl()
  {
    try {
      keystore = KeyStore.getInstance(KeyStore.getDefaultType());
      keystore.load(null, PASSWORD);
    }
    catch (KeyStoreException | IOException | NoSuchAlgorithmException | CertificateException ex) {
      throw Throwables.throwFormatted(ex,
                                      IllegalStateException.class,
                                      "Unable to create a keystore to process the keys!");
    }

    try {
      master = createMasterKeys();
    }
    catch (NoSuchAlgorithmException ex) {
      throw Throwables.throwFormatted(ex,
                                      IllegalStateException.class,
                                      "Unable to create a master key pair!");
    }
  }

  public void add(String alias, PublicKey entry)
  {
    publicKeys.put(alias, entry);
  }

  private KeyPair createMasterKeys() throws NoSuchAlgorithmException
  {
    KeyPairGenerator rsaGenerator = KeyPairGenerator.getInstance("RSA");
    rsaGenerator.initialize(2048);
    return rsaGenerator.generateKeyPair();
  }

  @Override
  @ContextAware(StatefulStreamCodec.class)
  public Introduction getPublicKey(Introduction client)
  {
    if (client.getKey().equals(publicKeys.get(client.getId()))) {
      return new BasicIntroduction("0.0.00", "master", master.getPublic());
    }

    return null;
  }

  public Introduction getPublicKey(StatefulStreamCodec<Object> codec, Introduction client)
  {
    StatefulStreamCodec<Object> unwrapped = StatefulStreamCodec.Synchronized.unwrapIfWrapped(codec);
    if (unwrapped instanceof CipherStatefulStreamCodec) {
      CipherStatefulStreamCodec<Object> serdes = (CipherStatefulStreamCodec<Object>)unwrapped;
      serdes.initCipher(CipherStatefulStreamCodec.getCipher(Cipher.ENCRYPT_MODE, client.getKey()),
                        CipherStatefulStreamCodec.getCipher(Cipher.DECRYPT_MODE, master.getPrivate()));
    }

    return getPublicKey(client);
  }

  @Override
  @ContextAware(StatefulStreamCodec.class)
  public Response establishSession(@NotNull Challenge challenge)
  {
    return new PKIResponse(0, challenge.getSecret());
  }

  public Response establishSession(StatefulStreamCodec<Object> codec, Challenge challenge)
  {
    StatefulStreamCodec<Object> unwrapped = StatefulStreamCodec.Synchronized.unwrapIfWrapped(codec);
    if (unwrapped instanceof CipherStatefulStreamCodec) {
      CipherStatefulStreamCodec<Object> serdes = (CipherStatefulStreamCodec<Object>)unwrapped;
      SecretKey key = new SecretKeySpec(challenge.getSecret(), "AES");
      IvParameterSpec iv = new IvParameterSpec(challenge.getInitializationVector());
      serdes.initCipher(CipherStatefulStreamCodec.getCipher(Cipher.ENCRYPT_MODE, key, iv),
                        CipherStatefulStreamCodec.getCipher(Cipher.DECRYPT_MODE, key, iv));
    }

    return establishSession(challenge);
  }

}
