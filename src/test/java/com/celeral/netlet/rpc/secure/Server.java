package com.celeral.netlet.rpc.secure;

import com.celeral.netlet.AbstractServer;
import com.celeral.netlet.rpc.Bean;
import com.celeral.netlet.rpc.ExecutingClient;
import com.celeral.netlet.rpc.methodserializer.ExternalizableMethodSerializer;

import java.nio.channels.SelectionKey;
import java.nio.channels.ServerSocketChannel;
import java.nio.channels.SocketChannel;
import java.security.KeyPair;
import java.util.Map;
import java.util.concurrent.Executor;

public class Server extends AbstractServer
{
  private final Executor executor;

  public static class CipherExecutingClient extends ExecutingClient
  {
    public CipherExecutingClient(Executor executor)
    {
      super(new Bean<Object>()
      {
        AuthenticatorImpl authenticatorImpl = new AuthenticatorImpl();

        {
          for (Map.Entry<String, KeyPair> entry : SecureRPCTest.clientKeys.keys.entrySet()) {
            authenticatorImpl.add(entry.getKey(), entry.getValue().getPublic());
          }
        }

        @Override
        public Object get(Object identifier)
        {
          if ("authenticator".equals(identifier)) {
            return authenticatorImpl;
          }

          if (identifier instanceof Authenticator.Response) {
            return new TransactionProcessor()
            {
              @Override
              public void process(Transaction<?> transaction)
              {
                System.out.println("Received transaction " + transaction);
              }

              @Override
              public void process(Payload<?> payload)
              {
                System.out.println("received payload " + payload);
              }
            };
          }

          return null;
        }
      }, ExternalizableMethodSerializer.SINGLETON, executor);
      super.setSerdes(SecureRPCTest.serdesProvider.newSerdes());
    }
  }

  public Server(Executor executor)
  {
    this.executor = executor;
  }

  @Override
  public ClientListener getClientConnection(SocketChannel client, ServerSocketChannel server)
  {
    return new CipherExecutingClient(executor);
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
