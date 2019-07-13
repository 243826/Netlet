package com.celeral.netlet.rpc.secure;

import java.lang.reflect.Method;
import java.net.SocketAddress;
import java.nio.channels.SelectionKey;
import java.nio.channels.ServerSocketChannel;
import java.nio.channels.SocketChannel;
import java.security.KeyPair;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.Executor;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.concurrent.atomic.AtomicBoolean;

import com.celeral.transaction.TransactionProcessor;
import com.celeral.transaction.processor.SerialTransactionProcessor;

import com.celeral.netlet.AbstractServer;
import com.celeral.netlet.codec.CipherStatefulStreamCodec;
import com.celeral.netlet.codec.DefaultStatefulStreamCodec;
import com.celeral.netlet.codec.StatefulStreamCodec;
import com.celeral.netlet.rpc.Bean;
import com.celeral.netlet.rpc.ExecutingClient;
import com.celeral.netlet.rpc.methodserializer.ExternalizableMethodSerializer;

public class Server extends AbstractServer
{
  private final Executor executor;
  AuthenticatorImpl iceBreaker = new AuthenticatorImpl();

  {
    for (Map.Entry<UUID, KeyPair> entry : SecureRPCTest.clientKeys.keys.entrySet()) {
      iceBreaker.add(entry.getKey(), entry.getValue().getPublic());
    }
  }

  TransactionProcessor stp = new SerialTransactionProcessor();

  private Bean<Object> bean = new Bean<Object>()
  {

    @Override
    public Object get(Object identifier, ExecutingClient client)
    {
      if ("hello".equals(identifier)) {
        return iceBreaker;
      }

      if (identifier instanceof Authenticator.Response) {
        return stp;
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
    return new AuthenticatedExecutingClient();
  }

  @Override
  public void registered(SelectionKey key)
  {
    super.registered(key);
    synchronized (serverAddressFuture) {
      serverAddressFuture.notify();
    }
  }

  @Override
  public SocketAddress getServerAddress()
  {
    SocketAddress serverAddress = super.getServerAddress();
    if (serverAddress != null) {
      return serverAddress;
    }

    throw new UnsupportedOperationException("Please use getServerAddressAsync method instead!");
  }


  private class ServerAddressFuture implements Future<SocketAddress>
  {
    AtomicBoolean cancelled = new AtomicBoolean();


    @Override
    public boolean cancel(boolean mayInterruptIfRunning)
    {
      cancelled.set(true);
      return true;
    }

    @Override
    public boolean isCancelled()
    {
      return cancelled.get();
    }

    @Override
    public boolean isDone()
    {
      if (isCancelled()) {
        throw new IllegalStateException("The future is already cancelled!");
      }

      return Server.super.getServerAddress() != null;
    }

    @Override
    public SocketAddress get() throws InterruptedException, ExecutionException
    {
      if (!isDone()) {
        synchronized (serverAddressFuture) {
          serverAddressFuture.wait();
        }
      }

      return Server.super.getServerAddress();
    }

    @Override
    public SocketAddress get(long timeout, TimeUnit unit) throws InterruptedException, ExecutionException, TimeoutException
    {
      if (!isDone()) {
        synchronized (serverAddressFuture) {
          unit.timedWait(serverAddressFuture, timeout);
        }
      }

      return Server.super.getServerAddress();
    }
  }

  private final ServerAddressFuture serverAddressFuture = new ServerAddressFuture();

  public Future<SocketAddress> getServerAddressAsync()
  {
    return serverAddressFuture;
  }

  class AuthenticatedExecutingClient extends ExecutingClient
  {
    UUID clientId; // is this the right place to pass on the client id?

    AuthenticatedExecutingClient()
    {
      super(Server.this.bean, ExternalizableMethodSerializer.SINGLETON, executor);
      DefaultStatefulStreamCodec<Object> codec = (DefaultStatefulStreamCodec<Object>)getSerdes();
//      try {
//        codec.register(Class.forName("sun.security.rsa.RSAPublicKeyImpl"), new JavaSerializer());
//      }
//      catch (ClassNotFoundException ex) {
//        throw new RuntimeException(ex);
//      }
      setSerdes(new CipherStatefulStreamCodec<>(codec, null, null));
    }

    @Override
    protected Object getContext(Object object, Method method, Class<?> contextType)
    {
      if (contextType == StatefulStreamCodec.class) {
        return getSerdes();
      }

      return null;
    }

  }
}
