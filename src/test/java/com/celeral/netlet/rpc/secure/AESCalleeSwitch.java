package com.celeral.netlet.rpc.secure;

import com.celeral.netlet.codec.CipherStatefulStreamCodec;
import com.celeral.netlet.codec.StatefulStreamCodec;
import com.celeral.netlet.rpc.Analyses;
import com.celeral.netlet.rpc.Client;
import com.celeral.utils.Throwables;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.lang.reflect.Method;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.AlgorithmParameterSpec;

public class AESCalleeSwitch implements Analyses.Analysis.PostAnalyzer<AuthenticatorImpl, Authenticator.Response>
{
  public static final String AES_CBC_PKCS_5_PADDING = "AES/CBC/PKCS5PADDING";
  public static final String AES_GCM_NO_PADDING = "AES/GCM/NoPadding";

  @Override
  public void analyze(Client<Client.RPC> client,
                      AuthenticatorImpl authenticator,
                      Method method, Object[] args,
                      Authenticator.Response retval, Throwable exception)
  {
    if (exception != null || retval == null) {
      return;
    }

    StatefulStreamCodec<Object> unwrappedSerdes = StatefulStreamCodec.Synchronized.unwrapIfWrapped(client.getSerdes());
    if (unwrappedSerdes instanceof CipherStatefulStreamCodec) {
      final CipherStatefulStreamCodec<Object> serdes = (CipherStatefulStreamCodec<Object>) unwrappedSerdes;

      SecretKey key = new SecretKeySpec(retval.getToken(), "AES");
      GCMParameterSpec iv = new GCMParameterSpec(128, ((Authenticator.Challenge)args[0]).getInitializationVector());
      final Cipher decryption = getCipher(Cipher.DECRYPT_MODE, key, iv);
      final Cipher encryption = getCipher(Cipher.ENCRYPT_MODE, key, iv);

      client.execute(new Runnable()
      {
        @Override
        public void run()
        {
          serdes.initCipher(encryption, decryption);
        }
      });
    }
  }

  public static Cipher getCipher(int mode, SecretKey key, AlgorithmParameterSpec iv)
  {
    try {
      final Cipher cipher = Cipher.getInstance(AES_GCM_NO_PADDING);
      cipher.init(mode, key, iv);
      return cipher;
    }
    catch (NoSuchAlgorithmException | InvalidKeyException | NoSuchPaddingException | InvalidAlgorithmParameterException ex) {
      throw Throwables.throwFormatted(ex, RuntimeException.class,
        "Unable to create {} mode instance of Cipher for key {}",
        mode, key);
    }
  }

}
