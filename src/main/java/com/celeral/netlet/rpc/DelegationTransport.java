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

  private final ConcurrentLinkedQueue<Object> deletedIdentifiers;
  private final WeakIdentityHashMap<Object, Object> identityMap;

  public DelegationTransport(ConnectionAgent agent,
                             TimeoutPolicy policy,
                             MethodSerializer<?> methodSerializer,
                             StatefulStreamCodec<Object> serdes,
                             Executor executor)
  {
    deletedIdentifiers = new ConcurrentLinkedQueue<>();
    identityMap = new WeakIdentityHashMap<>(1, v -> deletedIdentifiers.add(v));

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
      Object[] deletedIdentifiers;
      if (this.deletedIdentifiers.isEmpty()) {
        deletedIdentifiers = null;
      } else {
        deletedIdentifiers = this.deletedIdentifiers.toArray();
        logger.debug("requesting deletion of objects with identifiers = {}", this.deletedIdentifiers);
      }
      ProxyProvider.RPCFuture future = new ProxyProvider.RPCFuture(client.send(identity, method, args, deletedIdentifiers));
      futureResponses.add(future);

      try {
        final Object response = future.get(policy.getTimeoutMillis(), TimeUnit.MILLISECONDS);
        if (deletedIdentifiers != null) {
          for (Object identifier :  deletedIdentifiers) {
            if (!this.deletedIdentifiers.remove(identifier)) {
              logger.warn("identifier {} just removed from the list is missing from the list!", identifier);
            }
          }
        }
        return response;
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
