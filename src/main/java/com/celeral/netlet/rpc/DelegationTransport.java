package com.celeral.netlet.rpc;

import java.io.Closeable;
import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Method;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.Executor;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import com.celeral.netlet.codec.StatefulStreamCodec;
import com.celeral.utils.WeakIdentityHashMap;

public class DelegationTransport implements InvocationHandler, Closeable
{
  private final ConcurrentLinkedQueue<ProxyProvider.RPCFuture> futureResponses;
  public final ProxyProvider.DelegatingClient client;
  private final ConnectionAgent agent;
  private final TimeoutPolicy policy;

  private final WeakIdentityHashMap<Object, Object> identityMap;

  public DelegationTransport(ConnectionAgent agent,
                             TimeoutPolicy policy,
                             MethodSerializer<?> methodSerializer,
                             StatefulStreamCodec<Object> serdes,
                             Executor executor)
  {
    identityMap = new WeakIdentityHashMap<>();

    this.agent = agent;
    this.policy = policy;
    this.futureResponses = new ConcurrentLinkedQueue<>();
    this.client = new ProxyProvider.DelegatingClient(futureResponses, methodSerializer, executor);
    if (serdes != null) {
      this.client.setSerdes(serdes);
    }
  }

  public void register(Object identifier, Object proxy) {
    synchronized (identityMap) {
      identityMap.put(proxy, identifier);
    }
  }

  @Override
  public Object invoke(Object proxy, Method method, Object[] args) throws Throwable
  {
    Object identity = identityMap.get(proxy);
    do {
      if (!client.isConnected()) {
        agent.connect(client);
      }

      logger.trace("calling {}", method);
      ProxyProvider.RPCFuture future = new ProxyProvider.RPCFuture(client.send(identity, method, args));
      futureResponses.add(future);

      try {
        return future.get(policy.getTimeoutMillis(), TimeUnit.MILLISECONDS);
      }
      catch (TimeoutException ex) {
        policy.handleTimeout(this, ex);
      }
      catch (ExecutionException ex) {
        throw ex.getCause();
      }
    }
    while (true);
  }

  @Override
  public void close()
  {
    if (client != null) {
      if (client.isConnected()) {
        agent.disconnect(client);
      }
    }
  }

  public ProxyProvider.DelegatingClient getClient()
  {
    return client;
  }

  public static final Logger logger = LogManager.getLogger(DelegationTransport.class);
}
