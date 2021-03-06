/*
 * Copyright 2017 Celeral.
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

import java.lang.reflect.Method;
import java.lang.reflect.Proxy;
import java.util.Collections;
import java.util.Iterator;
import java.util.Map;
import java.util.WeakHashMap;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.Executor;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import com.celeral.netlet.EventLoop;
import com.celeral.netlet.rpc.Client.RPC;
import com.celeral.netlet.rpc.Client.RR;

/**
 * The class is abstract so that we can resolve the type T at runtime.
 *
 * @author Chetan Narsude {@literal <chetan@apache.org>}
 */
public class ProxyProvider
{
  public final DelegationTransport transport;
  private final BeanFactory beanFactory;

  /**
   * Future for tracking the asynchronous responses to the RPC call.
   */
  public static class RPCFuture implements Future<Object>
  {
    private final RPC rpc;
    AtomicReference<RR> rr;

    public RPCFuture(RPC rpc, RR rr)
    {
      this.rpc = rpc;
      this.rr = new AtomicReference<>(rr);
    }

    public RPCFuture(RPC rpc)
    {
      this(rpc, null);
    }

    @Override
    public boolean cancel(boolean mayInterruptIfRunning)
    {
      return false;
    }

    @Override
    public boolean isCancelled()
    {
      return false;
    }

    @Override
    public boolean isDone()
    {
      return rr.get() != null;
    }

    @Override
    public Object get() throws ExecutionException
    {
      RR r = rr.get();
      if (r.exception != null) {
        throw new ExecutionException(r.exception);
      }

      return r.response;
    }

    @Override
    public Object get(long timeout, TimeUnit unit) throws InterruptedException, ExecutionException, TimeoutException
    {
      if (rr.get() == null) {
        long diff = unit.toMillis(timeout);
        long waitUntil = System.currentTimeMillis() + diff;
        do {
          synchronized (rpc) {
            rpc.wait(diff);
          }

          if (rr.get() != null) {
            break;
          }
        }
        while ((diff = waitUntil - System.currentTimeMillis()) > 0);
      }

      RR r = rr.get();
      if (r == null) {
        throw new TimeoutException();
      }

      if (r.exception != null) {
        throw new ExecutionException(r.exception);
      }

      return r.response;
    }

  }

  @SuppressWarnings("unchecked")
  public ProxyProvider(DelegationTransport transport)
  {
    this.transport = transport;
    this.beanFactory =
            (BeanFactory) Proxy.newProxyInstance(BeanFactory.class.getClassLoader(), new Class<?>[]{BeanFactory.class}, transport);
  }

  public <T> T create(ClassLoader loader,
                      Class<?>[] desiredIfaces,
                      Object... args) {
     @SuppressWarnings("unchecked")
     T proxy = (T)Proxy.newProxyInstance(loader, desiredIfaces, transport);
     Object identifier = beanFactory.create(desiredIfaces, args);
     transport.register(identifier, proxy);
     return proxy;
  }

  public <T> T create(ClassLoader loader,
                      Class<?>[] desiredIfaces,
                      Class<?> concreteType,
                      Object... args) {
    @SuppressWarnings("unchecked")
    T proxy = (T) Proxy.newProxyInstance(loader, desiredIfaces, transport);
    Object identifier = beanFactory.create(concreteType, args);
    transport.register(identifier, proxy);
    return proxy;
  }


  public static class DelegatingClient extends Client<RR>
  {
    Map<Method, Integer> methodMap;
    Map<Object, Integer> identityMap;

    private final ConcurrentLinkedQueue<RPCFuture> futureResponses;
    private final MethodSerializer<Object> methodSerializer;

    DelegatingClient(ConcurrentLinkedQueue<RPCFuture> futureResponses, MethodSerializer<?> methodSerializer,
                     Executor executors)
    {
      super(executors);
      this.futureResponses = futureResponses;

      @SuppressWarnings("unchecked")
      MethodSerializer<Object> ms = (MethodSerializer<Object>)methodSerializer;
      this.methodSerializer = ms;

      methodMap = Collections.synchronizedMap(new WeakHashMap<Method, Integer>());
      identityMap = Collections.synchronizedMap(new WeakHashMap<Object, Integer>());
    }

    @Override
    public void onMessage(RR rr)
    {
      Iterator<RPCFuture> iterator = futureResponses.iterator();
      while (iterator.hasNext()) {
        RPCFuture next = iterator.next();
        int id = next.rpc.id;
        if (id == rr.id) {
          next.rr.set(rr);
          synchronized (next.rpc) {
            next.rpc.notifyAll();
          }
          iterator.remove();
          break;
        }
      }
    }

    static final AtomicInteger methodIdGenerator = new AtomicInteger();

    public RPC send(Object identifier, Method method, Object[] args, Object[] identifiers)
    {
      RPC rpc;

      Integer i = methodMap.get(method);
      if (i == null) {
        int id = methodIdGenerator.incrementAndGet();
        methodMap.put(method, id);
        rpc = new ExtendedRPC(methodSerializer.toSerializable(method), id, identifier, args);
      }
      else {
        rpc = new RPC(i, identifier, args);
      }

      if (identifiers != null) {
        rpc.setDeletedIdentifiers(identifiers);
      }

      send(rpc);
      return rpc;
    }

    @Override public void handleException(Exception cce, EventLoop el)
    {
      logger.info("got an exception {} on {}", cce, this);
      super.handleException(cce, el);
    }

    @Override public void disconnected()
    {
      logger.info("disconnected client {}", this);
      super.disconnected();
    }

    void notify(Exception ex) {
      RR rr = new RR();
      rr.exception = ex;

      Iterator<RPCFuture> iterator = futureResponses.iterator();
      while (iterator.hasNext()) {
        RPCFuture next = iterator.next();
        next.rr.set(rr);
        synchronized (next.rpc) {
          next.rpc.notifyAll();
        }
      }

      futureResponses.clear();
    }
  }

  public static final Logger logger = LogManager.getLogger(ProxyProvider.class);
}
