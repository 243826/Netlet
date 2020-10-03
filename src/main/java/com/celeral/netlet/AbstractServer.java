/*
 * Copyright (c) 2013 DataTorrent, Inc. ALL Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.celeral.netlet;

import java.net.SocketAddress;
import java.nio.channels.SelectionKey;
import java.nio.channels.ServerSocketChannel;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import com.celeral.netlet.Listener.ServerListener;
import com.celeral.utils.Throwables;

/**
 * <p>Abstract AbstractServer class.</p> *
 *
 * @since 1.0.0
 */
public abstract class AbstractServer implements ServerListener
{
  CompletableFuture<SocketAddress> boundSocketAddressFuture = new CompletableFuture<>();

  @Override
  public void registered(SelectionKey key)
  {
    boundSocketAddressFuture.complete(((ServerSocketChannel)key.channel()).socket().getLocalSocketAddress());
  }

  @Override
  public void unregistered(SelectionKey key)
  {
    boundSocketAddressFuture = null;
  }

  @Override
  public void handleException(Exception cce, EventLoop el)
  {
    if (boundSocketAddressFuture == null || boundSocketAddressFuture.isDone()) {
      logger.debug("", cce);
    }
    else {
      boundSocketAddressFuture.completeExceptionally(cce);
    }
  }

  @Deprecated
  /**
   * @deprecated use {@link #getBoundAddress()} instead
   */
  public SocketAddress getServerAddress()
  {
    try {
      return boundSocketAddressFuture.get();
    }
    catch (InterruptedException e) {
      throw Throwables.throwSneaky(e);
    }
    catch (ExecutionException e) {
      throw Throwables.throwSneaky(e.getCause());
    }
  }

  public CompletableFuture<SocketAddress> getBoundAddress() {
    return boundSocketAddressFuture;
  }

  private static final Logger logger = LogManager.getLogger(AbstractServer.class);
}
