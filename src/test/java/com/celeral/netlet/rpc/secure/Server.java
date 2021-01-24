package com.celeral.netlet.rpc.secure;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.lang.reflect.Method;
import java.nio.channels.ServerSocketChannel;
import java.nio.channels.SocketChannel;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyPair;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.Executor;
import java.util.function.Consumer;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import org.apache.commons.lang3.SystemUtils;

import com.celeral.netlet.AbstractServer;
import com.celeral.netlet.codec.CipherStatefulStreamCodec;
import com.celeral.netlet.codec.DefaultStatefulStreamCodec;
import com.celeral.netlet.codec.StatefulStreamCodec;
import com.celeral.netlet.rpc.BeanFactory;
import com.celeral.netlet.rpc.ExecutingClient;
import com.celeral.netlet.rpc.methodserializer.ExternalizableMethodSerializer;
import com.celeral.transaction.Transaction;
import com.celeral.transaction.TransactionProcessor;
import com.celeral.transaction.fileupload.UploadTransaction;
import com.celeral.transaction.processor.AbstractSerialTransactionProcessor;

public class Server extends AbstractServer
{
  private final Executor executor;

  public Server(Executor executor)
  {
    this.executor = executor;
  }

  static class UploadTransactionDocument implements UploadTransaction.Document {

    private final File file;

    UploadTransactionDocument(File file) {
      this.file = file;
    }

    @Override public OutputStream openOutputStream() throws IOException
    {
      return new FileOutputStream(file);
    }

    @Override public boolean delete() throws IOException
    {
      return file.delete();
    }

    @Override public boolean renameTo(String s) throws IOException
    {
      File file = new File(SystemUtils.getJavaIoTmpDir(), s);
      file.getParentFile().mkdirs();
      return this.file.renameTo(file);
    }

    public static final Logger logger = LogManager.getLogger(UploadTransactionDocument.class);
  }

  @Override
  public ClientListener getClientConnection(SocketChannel client, ServerSocketChannel server)
  {
    return new AuthenticatedExecutingClient(new BeanFactory() {
      private final HashMap<Object, Object> beanMap = new HashMap<>();

    AuthenticatorImpl iceBreaker = new AuthenticatorImpl();
    {
      for (Map.Entry<UUID, KeyPair> entry : SecureRPCTest.clientKeys.keys.entrySet()) {
        iceBreaker.add(entry.getKey(), entry.getValue().getPublic());
      }
    }

    TransactionProcessor stp = new AbstractSerialTransactionProcessor() {
      @Override public Transaction<?, ?> newTransaction()
      {
        return new UploadTransaction<UploadTransactionDocument>() {
          @Override public UploadTransactionDocument createTemporaryDocument(String s) throws IOException
          {
            return new UploadTransactionDocument(File.createTempFile("abc", null));
          }
        };
      }
    };

    Object getId(Object object) {
      return object.getClass().getSimpleName() + "@" + System.identityHashCode(object);
    }

    @Override public Object create(Class<?>[] desiredIfaces,  Object... args)
    {
      for (Class<?> iface : desiredIfaces) {
        if (iface == Authenticator.class) {
          Object id = getId(iceBreaker);
          beanMap.put(id, iceBreaker);
          return id;
        }

        if (iface == TransactionProcessor.class) {
          Object id = getId(stp);
          beanMap.put(id, stp);
          return id;
        }
      }

      return null;
    }

    @Override public Object create(Class<?> concreteType, Object... args)
    {
      if (Authenticator.class.isAssignableFrom(concreteType)) {
        Object id = getId(iceBreaker);
        beanMap.put(id, iceBreaker);
        return id;
      }

      if (TransactionProcessor.class.isAssignableFrom(concreteType)) {
        Object id = getId(stp);
        beanMap.put(id, stp);
        return id;
      }

      return null;
    }

      @Override public void destroy(Object id)
      {
        final Object remove = beanMap.remove(id);
        logger.trace("deleting the object {} with id {}", remove, id);
      }

      @Override public Object get(Object id)
      {
        if (id == null) {
          return this;
        }

        return beanMap.get(id);
      }

      @Override public boolean contains(Object id)
      {
        return beanMap.containsKey(id);
      }
    });
  }

//  @Override
//  public void registered(SelectionKey key)
//  {
//    super.registered(key);
//    synchronized (serverAddressFuture) {
//      serverAddressFuture.notify();
//    }
//  }
//
//  @Override
//  @Deprecated
//  /**
//   * @deprecated use {@link #getServerAddressAsync()} instead
//   */
//  public SocketAddress getServerAddress()
//  {
//    try {
//      return serverAddressFuture.get();
//    }
//    catch (InterruptedException e) {
//      throw Throwables.throwSneaky(e);
//    }
//    catch (ExecutionException e) {
//      throw Throwables.throwSneaky(e.getCause());
//    }
//  }
//
//  private class ServerAddressFuture implements Future<SocketAddress>
//  {
//    AtomicBoolean cancelled = new AtomicBoolean();
//
//
//    @Override
//    public boolean cancel(boolean mayInterruptIfRunning)
//    {
//      cancelled.set(true);
//      return true;
//    }
//
//    @Override
//    public boolean isCancelled()
//    {
//      return cancelled.get();
//    }
//
//    @Override
//    public boolean isDone()
//    {
//      return isCancelled() || Server.super.getServerAddress() != null;
//    }
//
//    @Override
//    public SocketAddress get() throws InterruptedException, ExecutionException
//    {
//      if (!isDone()) {
//        synchronized (serverAddressFuture) {
//          serverAddressFuture.wait();
//        }
//      }
//
//      return Server.super.getServerAddress();
//    }
//
//    @Override
//    public SocketAddress get(long timeout, TimeUnit unit) throws InterruptedException, ExecutionException, TimeoutException
//    {
//      if (isDone()) {
//        if (isCancelled()) {
//          throw new CancellationException();
//        }
//      }
//      else {
//        synchronized (serverAddressFuture) {
//          unit.timedWait(serverAddressFuture, timeout);
//        }
//      }
//
//      return Server.super.getServerAddress();
//    }
//  }

//  private final ServerAddressFuture serverAddressFuture = new ServerAddressFuture();

//  public Future<SocketAddress> getServerAddressAsync()
//  {
//    return serverAddressFuture;
//  }

  class AuthenticatedExecutingClient extends ExecutingClient
  {
    UUID clientId; // is this the right place to pass on the client id?

    AuthenticatedExecutingClient(BeanFactory beanFactory)
    {
      super(beanFactory, ExternalizableMethodSerializer.SINGLETON, executor);
      DefaultStatefulStreamCodec<Object> codec = (DefaultStatefulStreamCodec<Object>)getSerdes();
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

  public static final Logger logger = LogManager.getLogger(Server.class);
}
