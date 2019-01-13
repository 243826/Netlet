package com.celeral.netlet.rpc.secure;


import com.celeral.netlet.rpc.Analyses;
import com.celeral.netlet.util.Throwables;

import java.io.IOException;
import java.security.*;
import java.security.cert.CertificateException;
import java.util.HashMap;

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
                                      "Unable to create a keystore to process they keys!");
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
  @Analyses({@Analyses.Analysis(post = PKICalleeSwitch.class, domain = Analyses.Analysis.Domain.CALLEE)})
  public Introduction getPublicKey(Introduction client)
  {
    if (client.getKey().equals(publicKeys.get(client.getId()))) {
      return new PKIIntroduction("0.0.00", "master", master.getPublic());
    }

    return null;
  }

  @Override
  @Analyses({@Analyses.Analysis(post = AESCalleeSwitch.class, domain = Analyses.Analysis.Domain.CALLEE)})
  public Response establishSession(Challenge challenge)
  {
    return new PKIResponse(0, challenge.getToken());
  }

}
