package com.celeral.netlet.rpc.secure;

import java.nio.channels.SelectionKey;
import java.nio.channels.ServerSocketChannel;
import java.nio.channels.SocketChannel;
import java.security.KeyPair;
import java.util.Map;
import java.util.concurrent.Executor;

import com.esotericsoftware.kryo.serializers.JavaSerializer;

import com.celeral.netlet.AbstractServer;
import com.celeral.netlet.codec.CipherStatefulStreamCodec;
import com.celeral.netlet.codec.DefaultStatefulStreamCodec;
import com.celeral.netlet.rpc.Bean;
import com.celeral.netlet.rpc.ExecutingClient;
import com.celeral.netlet.rpc.methodserializer.ExternalizableMethodSerializer;

public class Server extends AbstractServer
{
  private final Executor executor;
  AuthenticatorImpl iceBreaker = new AuthenticatorImpl();

  {
    for (Map.Entry<String, KeyPair> entry : SecureRPCTest.clientKeys.keys.entrySet()) {
      iceBreaker.add(entry.getKey(), entry.getValue().getPublic());
    }
  }


  private Bean<Object> bean = new Bean<Object>()
  {

    @Override
    public Object get(Object identifier, ExecutingClient client)
    {
      if ("hello".equals(identifier)) {
        return iceBreaker;
      }

      if (identifier instanceof Authenticator.Response) {
        return new ConsoleTransactionProcessor();
      }

      return null;
    }
  };

  public Server(Executor executor)
  {
    this.executor = executor;
  }

  @Override
  public ClientListener getClientConnection(SocketChannel client, ServerSocketChannel server)
  {
    ExecutingClient ec = new ExecutingClient(bean, ExternalizableMethodSerializer.SINGLETON, executor);
    DefaultStatefulStreamCodec<Object> codec = (DefaultStatefulStreamCodec<Object>)ec.getSerdes();
    try {
      codec.register(Class.forName("sun.security.rsa.RSAPublicKeyImpl"), new JavaSerializer());
    }
    catch (ClassNotFoundException ex) {
      throw new RuntimeException(ex);
    }
    ec.setSerdes(new CipherStatefulStreamCodec<>(codec, null, null));
    return ec;
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
