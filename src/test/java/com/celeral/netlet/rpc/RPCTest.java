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

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.SocketAddress;
import java.nio.channels.SelectionKey;
import java.nio.channels.ServerSocketChannel;
import java.nio.channels.SocketChannel;
import java.util.concurrent.Executor;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

import com.celeral.utils.Throwables;

import org.junit.Assert;
import org.junit.Test;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import com.celeral.netlet.AbstractServer;
import com.celeral.netlet.DefaultEventLoop;
import com.celeral.netlet.rpc.ConnectionAgent.SimpleConnectionAgent;
import com.celeral.netlet.rpc.methodserializer.ExternalizableMethodSerializer;
import com.celeral.netlet.rpc.methodserializer.GenericStringBasedMethodSerializer;

/**
 * @author Chetan Narsude  <chetan@apache.org>
 */
public class RPCTest
{
  public interface Hello
  {
    void greet();

    boolean hasGreeted();
  }

  public static class HelloImpl implements Hello
  {
    boolean greeted;
    String scope;

    public HelloImpl(String scope)
    {
      this.scope = scope;
    }

    @Override
    public void greet()
    {
      logger.debug("greet = Hello {}!", scope);
      greeted = true;

      try {
        throw new Exception("root cause");
      }
      catch (Exception ex) {
        throw Throwables.throwFormatted(ex, RuntimeException.class, "Hello {}!", scope);
      }
    }

    @Override
    public boolean hasGreeted()
    {
      logger.debug("greeted = {}", greeted);
      return greeted;
    }

    private static final Logger logger = LogManager.getLogger(HelloImpl.class);
  }

  public static class Server extends AbstractServer
  {
    private final Executor executor;
    static final MethodSerializer<?> Generic_String_Based_Method_Serializer = new GenericStringBasedMethodSerializer(new Class<?>[]{Hello.class});

    public Server(Executor executor)
    {
      this.executor = executor;
    }

    @Override
    public ClientListener getClientConnection(SocketChannel client, ServerSocketChannel server)
    {
      ExecutingClient executingClient = new ExecutingClient(new Bean<Identity>()
      {
        HelloImpl helloIndia = new HelloImpl("India");
        HelloImpl helloWorld = new HelloImpl("World");

        @Override
        public Object get(Identity identifier, ExecutingClient client)
        {
          if ("hello-india".equals(identifier.name)) {
            return helloIndia;
          }

          return helloWorld;
        }
      }, ExternalizableMethodSerializer.SINGLETON, executor);
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

  @Test
  public void testRPCMultiThreaded() throws IOException, InterruptedException
  {
    ExecutorService executor = Executors.newFixedThreadPool(2);
    try {
      testRPC(executor);
    }
    finally {
      executor.shutdown();
    }
  }

  @Test
  public void testRPCSingleThreaded() throws IOException, InterruptedException
  {
    testRPC(new Executor()
    {
      @Override
      public void execute(Runnable command)
      {
        command.run();
      }
    });
  }

  public static class Identity
  {
    public String name;
  }

  public void testRPC(Executor executor) throws IOException, InterruptedException
  {
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

        SimpleConnectionAgent connectionAgent = new SimpleConnectionAgent(si, el);
        ProxyClient client = new ProxyClient(ExternalizableMethodSerializer.SINGLETON,
                                             executor);
        try (ProxyClient.DelegationTransport transport = client.new DelegationTransport(connectionAgent,
                                                                                        TimeoutPolicy.NO_TIMEOUT_POLICY,
                                                                                        null)) {
          Identity identity = new Identity();
          interact(client, transport, identity);

          identity.name = "hello-india";
          interact(client, transport, identity);
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

  private void interact(ProxyClient client, ProxyClient.DelegationTransport transport, Identity identity)
  {
    Hello hello = client.create(identity, Hello.class, transport);
    Assert.assertFalse("Before Greeted!", hello.hasGreeted());

    try {
      hello.greet();
    }
    catch (RuntimeException ex) {
      logger.debug("remote exception", ex);
      Assert.assertEquals("hello-india".equals(identity.name) ? "Hello India!" : "Hello World!", ex.getMessage());
    }

    Assert.assertTrue("After Greeted!", hello.hasGreeted());
  }

  private static final Logger logger = LogManager.getLogger(RPCTest.class);
}
