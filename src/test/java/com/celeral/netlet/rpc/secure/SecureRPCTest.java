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

import java.io.File;
import java.io.IOException;
import java.lang.reflect.Proxy;
import java.net.InetSocketAddress;
import java.net.SocketAddress;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.util.HashMap;
import java.util.Random;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import com.celeral.utils.NamedThreadFactory;
import com.esotericsoftware.kryo.serializers.JavaSerializer;

import org.junit.Assert;
import org.junit.Test;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import org.apache.commons.lang3.SystemUtils;

import com.celeral.netlet.DefaultEventLoop;
import com.celeral.netlet.codec.CipherStatefulStreamCodec;
import com.celeral.netlet.codec.DefaultStatefulStreamCodec;
import com.celeral.netlet.codec.StatefulStreamCodec;
import com.celeral.netlet.codec.StatefulStreamCodec.Synchronized;
import com.celeral.netlet.rpc.ConnectionAgent.SimpleConnectionAgent;
import com.celeral.netlet.rpc.ProxyClient;
import com.celeral.netlet.rpc.SerdesProvider;
import com.celeral.netlet.rpc.TimeoutPolicy;
import com.celeral.netlet.rpc.methodserializer.ExternalizableMethodSerializer;
import com.celeral.netlet.rpc.secure.transaction.TransactionProcessor;
import com.celeral.netlet.rpc.secure.upload.UploadTransaction;
import com.celeral.netlet.util.Throwables;

/**
 * @author Chetan Narsude  <chetan@apache.org>
 */
public class SecureRPCTest
{
  public static final String CHARSET_UTF_8 = "UTF-8";

  static class CipherSerdesProvider implements SerdesProvider
  {
    @Override
    public StatefulStreamCodec<Object> newSerdes(StatefulStreamCodec<Object> serdes)
    {
      return createSerdes(serdes);
    }

    public static StatefulStreamCodec<Object> createSerdes(StatefulStreamCodec<Object> serdes)
    {
      DefaultStatefulStreamCodec<Object> codec = (DefaultStatefulStreamCodec<Object>)serdes;
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

  public static CipherSerdesProvider serdesProvider = new CipherSerdesProvider();

  private void authenticate(ProxyClient client, ProxyClient.DelegationTransport transport)
  {
    final String alias = Integer.toString(new Random(System.currentTimeMillis()).nextInt(clientKeys.keys.size()));
    final KeyPair clientKeyPair = clientKeys.keys.get(alias);

    Authenticator authenticator = client.create("hello",
                                                Authenticator.class.getClassLoader(),
                                                new Class<?>[]{Authenticator.class},
                                                transport);
      StatefulStreamCodec<Object> unwrapped = Synchronized.unwrapIfWrapped(transport.client.getSerdes());
      if (unwrapped instanceof CipherStatefulStreamCodec) {
        CipherStatefulStreamCodec<Object> serdes = (CipherStatefulStreamCodec<Object>)unwrapped;
        serdes.initCipher(null,
                          CipherStatefulStreamCodec.getCipher(Cipher.DECRYPT_MODE, clientKeyPair.getPrivate()));
      }

      final BasicIntroduction clientIntro = new BasicIntroduction("0.0.00", alias, clientKeyPair.getPublic());
      final Authenticator.Introduction serverIntro = authenticator.getPublicKey(clientIntro);

      if (areCompatible(clientIntro, serverIntro)) {
        PKIChallenge challenge = new PKIChallenge(alias);
        if (unwrapped instanceof CipherStatefulStreamCodec) {
          CipherStatefulStreamCodec<Object> serdes = (CipherStatefulStreamCodec<Object>)unwrapped;
          SecretKey key = new SecretKeySpec(challenge.getSecret(), "AES");
          IvParameterSpec iv = new IvParameterSpec(challenge.getInitializationVector());
          serdes.initCipher(CipherStatefulStreamCodec.getCipher(Cipher.ENCRYPT_MODE, serverIntro.getKey()),
                            CipherStatefulStreamCodec.getCipher(Cipher.DECRYPT_MODE, key, iv));
        }

        Authenticator.Response response = authenticator.establishSession(challenge);
        Assert.assertArrayEquals(challenge.getSecret(), response.getSecret());
        logger.debug("{} == {}", challenge.getSecret(), response.getSecret());

        if (unwrapped instanceof CipherStatefulStreamCodec) {
          CipherStatefulStreamCodec<Object> serdes = (CipherStatefulStreamCodec<Object>)unwrapped;
          SecretKey key = new SecretKeySpec(response.getSecret(), "AES");
          IvParameterSpec iv = new IvParameterSpec(challenge.getInitializationVector());
          serdes.initCipher(CipherStatefulStreamCodec.getCipher(Cipher.ENCRYPT_MODE, key, iv),
                            CipherStatefulStreamCodec.getCipher(Cipher.DECRYPT_MODE, key, iv));
        }
        transact(client, transport, response, challenge);
      }
  }

  private boolean areCompatible(BasicIntroduction clientIntro, Authenticator.Introduction serverIntro)
  {
    return true;
  }

  private void transact(ProxyClient client, ProxyClient.DelegationTransport transport, Authenticator.Response response, Authenticator.Challenge challenge)
  {
    Assert.assertArrayEquals(challenge.getSecret(), response.getSecret());
    /*
     * we are very sure here that our communication is secure at this point!
     */
    TransactionProcessor transactionProcessor = client.create(response,
                                                              TransactionProcessor.class.getClassLoader(),
                                                              new Class<?>[]{TransactionProcessor.class},
                                                              transport);
    try (ProxyClient.DelegationTransport store = (ProxyClient.DelegationTransport)Proxy.getInvocationHandler(transactionProcessor)) {
      StatefulStreamCodec<Object> unwrapped = Synchronized.unwrapIfWrapped(store.client.getSerdes());
      if (unwrapped instanceof CipherStatefulStreamCodec) {
        CipherStatefulStreamCodec<Object> serdes = (CipherStatefulStreamCodec<Object>)unwrapped;
        SecretKey key = new SecretKeySpec(response.getSecret(), "AES");
        //GCMParameterSpec iv = new GCMParameterSpec(128, challenge.getInitializationVector());
        IvParameterSpec iv = new IvParameterSpec(challenge.getInitializationVector());
        serdes.initCipher(CipherStatefulStreamCodec.getCipher(Cipher.ENCRYPT_MODE, key, iv),
                          CipherStatefulStreamCodec.getCipher(Cipher.DECRYPT_MODE, key, iv));
      }

      String filename = "SecureRPCTest.class";
      File source = new File("target/test-classes/com/celeral/netlet/rpc/secure", filename);
      File destination = new File(SystemUtils.getJavaIoTmpDir(), filename);

      try {
        if (destination.exists()) {
          destination.delete();
        }

        UploadTransaction transaction = new UploadTransaction(source.toString(), 1024);
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

      try {
        while (!destination.exists()) {
          Thread.sleep(5);
        }

        Assert.assertArrayEquals("files identical",
                                 Files.readAllBytes(Paths.get(source.toString())), Files.readAllBytes(Paths.get(destination.toString())));
      }
      catch (Exception ex) {
        Throwables.wrapIfChecked(ex);
      }
    }
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

          SimpleConnectionAgent connectionAgent = new SimpleConnectionAgent(si, el);
          ProxyClient client = new ProxyClient(ExternalizableMethodSerializer.SINGLETON,
                                               clientExecutor);
          try (ProxyClient.DelegationTransport transport = client.new DelegationTransport(connectionAgent,
                                                                                     TimeoutPolicy.NO_TIMEOUT_POLICY,
                                                                                     null)) {
            transport.client.setSerdes(serdesProvider.newSerdes(transport.client.getSerdes()));
            authenticate(client, transport);
          }
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


  private static final Logger logger = LoggerFactory.getLogger(SecureRPCTest.class);
}
