/*
 * Copyright 2017 Celeral <netlet@celeral.com>.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.celeral.netlet.rpc.secure;

import java.io.IOException;
import java.lang.reflect.Proxy;
import java.net.InetSocketAddress;
import java.net.SocketAddress;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.HashMap;
import java.util.Random;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import com.celeral.netlet.rpc.*;
import com.celeral.netlet.rpc.secure.upload.UploadTransaction;
import com.esotericsoftware.kryo.serializers.JavaSerializer;

import org.junit.Assert;
import org.junit.Test;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.celeral.netlet.DefaultEventLoop;
import com.celeral.netlet.codec.CipherStatefulStreamCodec;
import com.celeral.netlet.codec.DefaultStatefulStreamCodec;
import com.celeral.netlet.codec.StatefulStreamCodec;
import com.celeral.netlet.codec.StatefulStreamCodec.Synchronized;
import com.celeral.netlet.rpc.ConnectionAgent.SimpleConnectionAgent;
import com.celeral.netlet.rpc.methodserializer.ExternalizableMethodSerializer;
import com.celeral.netlet.util.Throwables;
import com.celeral.utils.NamedThreadFactory;

/**
 * @author Chetan Narsude  <chetan@apache.org>
 */
public class SecureRPCTest
{
  public static final String CHARSET_UTF_8 = "UTF-8";

  static class MySerdesProvider implements SerdesProvider
  {
    @Override
    public StatefulStreamCodec<Object> newSerdes()
    {
      DefaultStatefulStreamCodec<Object> codec = new DefaultStatefulStreamCodec<>();
      try {
        codec.register(Class.forName("sun.security.rsa.RSAPublicKeyImpl"), new JavaSerializer());
        return Synchronized.wrap(new CipherStatefulStreamCodec<>(codec, null, null));
      }
      catch (ClassNotFoundException ex) {
        throw Throwables.throwFormatted(ex, IllegalStateException.class,
                                        "Unable to initialize the serializer/deserializer!");
      }
    }
  }

  public static MySerdesProvider serdesProvider = new MySerdesProvider();

  private void authenticate(ProxyClient client, String identity)
  {
    Authenticator authenticator = client.create(identity,
                                                Authenticator.class.getClassLoader(),
                                                new Class<?>[]{Authenticator.class},
                                                serdesProvider);
    try (ProxyClient.InvocationHandlerImpl impl = (ProxyClient.InvocationHandlerImpl) Proxy.getInvocationHandler(authenticator)) {
      final String alias = Integer.toString(new Random(System.currentTimeMillis()).nextInt(clientKeys.keys.size()));
      final KeyPair clientKeyPair = clientKeys.keys.get(alias);

      final PKIIntroduction clientIntro = new PKIIntroduction("0.0.00", alias, clientKeyPair.getPublic());
      Authenticator.Introduction serverIntro = authenticator.getPublicKey(clientIntro);

      StatefulStreamCodec<Object> unwrapped = Synchronized.unwrapIfWrapped(impl.client.getSerdes());
      if (unwrapped instanceof CipherStatefulStreamCodec) {
        CipherStatefulStreamCodec<Object> serdes = (CipherStatefulStreamCodec<Object>) unwrapped;
        serdes.initCipher(PKICalleeSwitch.getCipher(Cipher.ENCRYPT_MODE, serverIntro.getKey()),
                          PKICalleeSwitch.getCipher(Cipher.DECRYPT_MODE, clientKeyPair.getPrivate()));
      }

      PKIChallenge challenge = new PKIChallenge(alias);
      Authenticator.Response response = authenticator.establishSession(challenge);

      transact(client, response, challenge);
    }
  }

  private void transact(ProxyClient client, Authenticator.Response response,  Authenticator.Challenge challenge)
  {
    Assert.assertArrayEquals(challenge.getToken(), response.getToken());
    /*
     * we are very sure here that our communication is secure at this point!
     */
    TransactionProcessor transactionProcessor = client.create(response,
                                                              TransactionProcessor.class.getClassLoader(),
                                                              new Class<?>[]{TransactionProcessor.class},
                                                              serdesProvider);
    try (ProxyClient.InvocationHandlerImpl store = (ProxyClient.InvocationHandlerImpl) Proxy.getInvocationHandler(transactionProcessor)) {
      StatefulStreamCodec<Object> unwrapped = Synchronized.unwrapIfWrapped(store.client.getSerdes());
      if (unwrapped instanceof CipherStatefulStreamCodec) {
        CipherStatefulStreamCodec<Object> serdes = (CipherStatefulStreamCodec<Object>) unwrapped;
        SecretKey key = new SecretKeySpec(response.getToken(), "AES");
        GCMParameterSpec iv = new GCMParameterSpec(128, challenge.getInitializationVector());
        serdes.initCipher(AESCalleeSwitch.getCipher(Cipher.ENCRYPT_MODE, key, iv),
                          AESCalleeSwitch.getCipher(Cipher.DECRYPT_MODE, key, iv));
      }


      try {
        UploadTransaction transaction = new UploadTransaction("target/test-classes/com/celeral/netlet/rpc/secure/SecureRPCTest.class", 1024);
        transactionProcessor.process(transaction);
        try (UploadTransaction.UploadPayloadIterator uploadIterator = transaction.getPayloadIterator()) {
          while (uploadIterator.hasNext()) {
            transactionProcessor.process(uploadIterator.next());
          }
        }
      }
      catch (IOException ex) {
        throw new RuntimeException(ex);
      }
    }
  }


  private static SecureRandom random = new SecureRandom();

  public static byte[] getRandomBytes(int size)
  {
    byte[] bytes = new byte[size];
    random.nextBytes(bytes);
    return bytes;
  }


  public static class ClientKeys
  {
    HashMap<String, KeyPair> keys;

    public ClientKeys()
    {
      final int initialCapacity = 10;
      keys = new HashMap<>(initialCapacity);
      populateKeys(initialCapacity);
    }

    private void populateKeys(int count)
    {
      try {
        KeyPairGenerator rsaGenerator = KeyPairGenerator.getInstance("RSA");
        rsaGenerator.initialize(2048);

        for (int i = 0; i < count; i++) {
          keys.put(Integer.toString(i), rsaGenerator.generateKeyPair());
        }
      }
      catch (NoSuchAlgorithmException ex) {
        throw Throwables.throwFormatted(ex,
                                        IllegalStateException.class,
                                        "Unable to populate the keypairs for the clients");
      }
    }
  }

  static ClientKeys clientKeys = new ClientKeys();

  @Test
  public void testAuthenticator() throws IOException, InterruptedException
  {
    ExecutorService serverExecutor = Executors.newFixedThreadPool(2, new NamedThreadFactory(new ThreadGroup("server")));
    ExecutorService clientExecutor = Executors.newFixedThreadPool(2, new NamedThreadFactory(new ThreadGroup("client")));

    try {
      DefaultEventLoop el = DefaultEventLoop.createEventLoop("rpc");
      el.start();
      try {
        Server server = new Server(serverExecutor);
        el.start(new InetSocketAddress(0), server);

        try {
          SocketAddress si;
          synchronized (server) {
            while ((si = server.getServerAddress()) == null) {
              server.wait();
            }
          }

          ProxyClient client = new ProxyClient(new SimpleConnectionAgent(si, el),
                                               TimeoutPolicy.NO_TIMEOUT_POLICY,
                                               ExternalizableMethodSerializer.SINGLETON,
                                               clientExecutor);
          String identity = "authenticator";
          authenticate(client, identity);
        }
        finally {
          el.stop(server);
        }
      }
      finally {
        el.stop();
      }

    }
    finally {
      serverExecutor.shutdown();
    }
  }


  private static final Logger logger = LoggerFactory.getLogger(Authenticator.class);
}
