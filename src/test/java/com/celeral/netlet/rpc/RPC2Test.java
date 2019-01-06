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
package com.celeral.netlet.rpc;

import java.io.Closeable;
import java.io.IOException;
import java.lang.reflect.Proxy;
import java.net.InetSocketAddress;
import java.net.SocketAddress;
import java.nio.channels.SelectionKey;
import java.nio.channels.ServerSocketChannel;
import java.nio.channels.SocketChannel;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.CertificateException;
import java.util.HashMap;
import java.util.Map.Entry;
import java.util.Random;
import java.util.concurrent.Executor;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.validation.constraints.NotNull;
import javax.validation.constraints.Size;

import com.esotericsoftware.kryo.serializers.FieldSerializer;
import com.esotericsoftware.kryo.serializers.JavaSerializer;

import org.junit.Assert;
import org.junit.Test;

import com.celeral.netlet.AbstractServer;
import com.celeral.netlet.DefaultEventLoop;
import com.celeral.netlet.codec.DefaultStatefulStreamCodec;
import com.celeral.netlet.codec.StatefulStreamCodec;
import com.celeral.netlet.rpc.ConnectionAgent.SimpleConnectionAgent;
import com.celeral.netlet.rpc.RPC2Test.Authenticator.Challenge;
import com.celeral.netlet.rpc.methodserializer.ExternalizableMethodSerializer;
import com.celeral.netlet.util.Throwables;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 *
 * @author Chetan Narsude  <chetan@apache.org>
 */
public class RPC2Test
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
        return codec;
      }
      catch (ClassNotFoundException ex) {
        throw Throwables.throwFormatted(ex, IllegalStateException.class,
                                        "Unable to initialize the serializer/deserializer!");
      }
    }
  }

  static MySerdesProvider serdesProvider = new MySerdesProvider();

  public static byte[] encrypt(PublicKey key, byte[] plaintext) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException
  {
    Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA1AndMGF1Padding");
    cipher.init(Cipher.ENCRYPT_MODE, key);
    return cipher.doFinal(plaintext);
  }

  public static byte[] decrypt(PrivateKey key, byte[] ciphertext) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException
  {
    Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA1AndMGF1Padding");
    cipher.init(Cipher.DECRYPT_MODE, key);
    return cipher.doFinal(ciphertext);
  }

  private void authenticate(ProxyClient client, Identity identity) throws IOException
  {
    Authenticator authenticator = client.create(identity,
                                                Authenticator.class.getClassLoader(),
                                                new Class<?>[]{Authenticator.class},
                                                serdesProvider
    );
    try {
      final String alias = Integer.toString(new Random(System.currentTimeMillis()).nextInt(clientKeys.keys.size()));
      final PKIIntroduction clientIntro = new PKIIntroduction("0.0.00", alias, clientKeys.keys.get(alias).getPublic());

      Authenticator.Introduction serverIntro = authenticator.getPublicKey(clientIntro);

      PKIChallenge challenge = new PKIChallenge(alias);
      Authenticator.Response response = authenticator.establishSession(challenge);
      Assert.assertArrayEquals(challenge.getToken(), response.getToken());
      logger.debug("{} == {}", challenge.getToken(), response.getToken());
    }
    finally {
      ((Closeable)Proxy.getInvocationHandler(authenticator)).close();
    }
  }

  private static final Logger logger = LoggerFactory.getLogger(Authenticator.class);
  
  public static class PKIIntroduction implements Authenticator.Introduction
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

  static Random random = new Random(System.currentTimeMillis());

  public static byte[] getRandomBytes(int size)
  {
    byte[] bytes = new byte[size];
    random.nextBytes(bytes);
    return bytes;
  }

  public static class PKIChallenge implements Authenticator.Challenge
  {
    String id;
    byte[] token;

    private PKIChallenge()
    {
      /* jlto */
    }
    
    public PKIChallenge(String id)
    {
      this.id = id;
      this.token = getRandomBytes(16);
    }

    @Override
    public String getId()
    {
      return id;
    }

    @Override
    public byte[] getToken()
    {
      return token;
    }

  }

  public static class PKIResponse implements Authenticator.Response
  {
    int sessionId;
    byte[] token;
    byte[] secret;

    private PKIResponse()
    {
      /* jlto */
    }
    
    public PKIResponse(int sessionId, byte[] token)
    {
      this.sessionId = sessionId;
      this.token = token;
      this.secret = getRandomBytes(16);
    }

    @Override
    public byte[] getToken()
    {
      return token;
    }

    @Override
    public int getSessionId()
    {
      return sessionId;
    }

    @Override
    public byte[] getSecret()
    {
      return secret;
    }

  }

  public interface Authenticator
  {
    interface Introduction
    {
      /**
       * Id of the entity which is being introduced using this object.
       *
       * @return the id of the entity represented
       */
      String getId();

      /**
       * The semantic version of the protocol the entity can talk.
       *
       * @return a version string in semver format
       */
      String getVersion();

      /**
       * Public key of the entity.
       * By presenting the public key, it's being claimed that the data encrypted with the public key
       * can be decrypted by the entity which presents this public key. With the current limitations
       * of the technology it means that the entity possesses the corresponding private key as well.
       *
       * @return
       */
      PublicKey getKey();
    }

    /**
     * Objects of this type are presented by the entity wishing to establish a trusted secure session
     * with other entities. The serialized bytes of this object are encrypted with the public key of
     * the entity on the other end. This way the other entity will only be able to decrypt the token
     * if it has the private key for the public key it previously presented.
     */
    interface Challenge
    {
      /**
       * Gets the id of the entity which wishes to establish the session. This id is used to locate
       * the public key of the client so that the response to the client can be encrypted.
       *
       * @return id of the entity initiating request for the session
       */
      String getId();

      /**
       * Randomly generated token either 16 bytes long or 32 bytes long which
       *
       * @return random sequence of bytes
       */
      @Size(min = 16, max = 32)
      byte[] getToken();
    }

    /**
     * Objects of this type are presented by the entity entering into a trusted secure session
     * with the entities which expressed interest to create such a session. The serialized bytes of this
     * object are encrypted with the public key of the entity on the other end. This way the other entity
     * will only be able to decrypt the token if has the private key for the public key it previously
     * presented to introduce itself.
     */
    interface Response
    {
      /**
       * Decrypted tokens
       *
       * @return
       */
      byte[] getToken();

      public int getSessionId();

      /**
       * Session identifier which can be used to encrypt the data for the session.
       *
       * @return
       */
      byte[] getSecret();
    }

    /**
     * Introduce the client to the server using the publickey and id to assist with fast identification.
     *
     * @param client introduction of the caller
     *
     * @return introduction of the callee if it recognizes the caller and wants to chat with it
     */
    public Introduction getPublicKey(Introduction client);

    /**
     * Prove the identity of the client to the server and vice a versa thus establishing trust and creating a secure session for communication.
     * The client sends the server a payload which is encrypted by the
     *
     * @param challenge serialized bytes of object of type {@link Challenge}
     *
     * @return serialized bytes of object of type {@link Response}
     */
    public Response establishSession(@NotNull Challenge challenge);
  }

  public static class AuthenticatorImpl implements Authenticator
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
                                        "Unable to create a keystore to store they keys!");
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
    public Introduction getPublicKey(Introduction client)
    {
      if (client.getKey().equals(publicKeys.get(client.getId()))) {
        return new PKIIntroduction("0.0.00", "master", master.getPublic());
      }

      return null;
    }

    @Override
    public Response establishSession(Challenge challenge)
    {
      return new PKIResponse(0, challenge.getToken());
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

  public static class Server extends AbstractServer
  {
    private final Executor executor;

    public Server(Executor executor)
    {
      this.executor = executor;
    }

    @Override
    public ClientListener getClientConnection(SocketChannel client, ServerSocketChannel server)
    {
      ExecutingClient executingClient = new ExecutingClient(new Bean<Identity>()
      {
        AuthenticatorImpl authenticatorImpl = new AuthenticatorImpl();

        {
          for (Entry<String, KeyPair> entry : clientKeys.keys.entrySet()) {
            authenticatorImpl.add(entry.getKey(), entry.getValue().getPublic());
          }
        }

        @Override
        public Object get(Identity identifier)
        {
          return authenticatorImpl;
        }
      }, ExternalizableMethodSerializer.SINGLETON, executor);
      executingClient.setSerdes(serdesProvider.newSerdes());
      return executingClient;
    }

    @Override
    public void registered(SelectionKey key)
    {
      super.registered(key);
      synchronized (this) {
        notify();
      }
    }

  }

  static ClientKeys clientKeys = new ClientKeys();

  @Test
  public void testAuthenticator() throws IOException, InterruptedException
  {
    ExecutorService executor = Executors.newFixedThreadPool(2);
    try {
      DefaultEventLoop el = DefaultEventLoop.createEventLoop("rpc");
      el.start();
      try {
        Server server = new Server(executor);
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
                                               executor);
          Identity identity = new Identity();
          identity.name = "authenticator";
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
      executor.shutdown();
    }
  }

  public static class Identity
  {
    public String name;
  }

}
