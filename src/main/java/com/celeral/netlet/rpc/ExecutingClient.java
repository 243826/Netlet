/*
 * Copyright 2018 Celeral.
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

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executor;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import com.celeral.netlet.EventLoop;
import com.celeral.netlet.rpc.methodserializer.ExternalizableMethodSerializer;
import com.celeral.utils.Throwables;

/**
 *
 * @author Chetan Narsude <chetan@celeral.com>
 */
public class ExecutingClient extends Client<Client.RPC>
{
  protected final BeanFactory beanFactory;
  private final ConcurrentHashMap<Integer, Method> methodMap;
  private final ConcurrentHashMap<Integer, Integer> notifyMap;
  private final MethodSerializer<Object> methodSerializer;

  @SuppressWarnings("unchecked")
  public ExecutingClient(BeanFactory beanFactory, MethodSerializer<?> methodSerializer, Executor executor)
  {
    super(executor);
    this.beanFactory = beanFactory;
    this.methodSerializer = (MethodSerializer<Object>)methodSerializer;
    this.methodMap = new ConcurrentHashMap<>();
    this.notifyMap = new ConcurrentHashMap<>();
  }

  public ExecutingClient(BeanFactory beanFactory, Executor executor)
  {
    this(beanFactory, ExternalizableMethodSerializer.SINGLETON, executor);
  }

  @Override
  @SuppressWarnings("UseSpecificCatch")
  public void onMessage(Client.RPC message)
  {
    ArrayList<Object> deletedIdentifiers = null;
    if (message.deletedIdentifiers != null) {
      deletedIdentifiers = new ArrayList<>(message.deletedIdentifiers.length);
      for (Object identifier : message.deletedIdentifiers) {
        if (beanFactory.contains(identifier)) {
          beanFactory.destroy(identifier);
          deletedIdentifiers.add(identifier);
        }
      }
    }

    Client.RR rr;
    Method method = null;

    final Object object = beanFactory.get(message.identifier);
    Integer methodId = message.methodId;
    try {
      if (message instanceof Client.ExtendedRPC) {
        method = methodSerializer.fromSerializable(((Client.ExtendedRPC)message).serializableMethod);
        if (method == null) {
          throw Throwables.throwFormatted(NoSuchMethodException.class,
                                          "Missing method {} for identifier {}!",
                                          ((Client.ExtendedRPC)message).serializableMethod, message.identifier);
        }
        else {
          methodMap.put(methodId, method);
          Integer waiters = notifyMap.remove(methodId);
          if (waiters != null) {
            synchronized (waiters) {
              waiters.notifyAll();
            }
          }
        }
      }
      else {
        method = methodMap.get(methodId);
        if (method == null) {
          Integer old = notifyMap.putIfAbsent(methodId, methodId);
          if (old != null) {
            methodId = old;
          }

          synchronized (methodId) {
            /* 
             * checking the method again, takes care of a race condition
             * between the time method was not found by this code and
             * another thread put the method and sent the signal.
             */
            while ((method = methodMap.get(methodId)) == null) {
              // arbitrary wait for 1 second; we should make this configurable!
              methodId.wait(1000);
            }
          }

          if (method == null) {
            throw Throwables.throwFormatted(IllegalStateException.class,
                                            "Missing mapping for message {}!",
                                            message);
          }
        }
      }

      Object retval;

      Method objectMethod = object.getClass().getMethod(method.getName(), method.getParameterTypes());
      objectMethod.setAccessible(true);

      ContextAware annotation = objectMethod.getAnnotation(ContextAware.class);
      if (annotation == null) {
        /* since annotation was not found, we just find the method and invoke it. */
        retval = objectMethod.invoke(object, message.args);
      }
      else {
        Class<?>[] types = method.getParameterTypes();
        if (types.length == 0) {
          objectMethod = object.getClass().getMethod(method.getName(), annotation.value());
          retval = objectMethod.invoke(object, getContext(object, method, annotation.value()));
        }
        else {
          Class<?>[] newTypes = new Class<?>[types.length + 1];
          newTypes[0] = annotation.value();
          int t = 1;
          for (Class<?> type : types) {
            newTypes[t++] = type;
          }
          objectMethod = object.getClass().getMethod(method.getName(), newTypes);

          Object[] arguments = new Object[message.args.length + 1];
          arguments[0] = getContext(object, method, annotation.value());
          int o = 1;
          for (Object arg : message.args) {
            arguments[o++] = arg;
          }

          retval = objectMethod.invoke(object, arguments);
        }
      }

      rr = new Client.RR(message.id, retval);
    }
    catch (InvocationTargetException ex) {
      rr = new Client.RR(message.id, null, ex.getCause());
    }
    catch (Exception ex) {
      rr = new Client.RR(message.id, null, ex);
    }

    if (deletedIdentifiers != null && !deletedIdentifiers.isEmpty()) {
      rr.removedIdentifiers = deletedIdentifiers.toArray();
    }

    logger.trace("responding to {}", method);
    send(rr);
  }

  protected Object getContext(Object object, Method method, Class<?> contextType)
  {
    return null;
  }

  @Override public void disconnected()
  {
    logger.info("disconnected {}!", this);
    super.disconnected();
  }

  @Override public void handleException(Exception cce, EventLoop el)
  {
    logger.info("connection dropped for client {} - execution id = {}", this, Thread.currentThread(), cce);
  }

  private static final Logger logger = LogManager.getLogger(ExecutingClient.class);
}
