package com.celeral.netlet.rpc.secure.upload;

import java.io.Closeable;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.RandomAccessFile;
import java.util.Iterator;
import java.util.concurrent.atomic.AtomicLong;

import com.esotericsoftware.kryo.serializers.FieldSerializer;
import com.esotericsoftware.kryo.serializers.JavaSerializer;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.celeral.netlet.rpc.secure.transaction.ExecutionContext;
import com.celeral.netlet.rpc.secure.transaction.Payload;
import com.celeral.netlet.rpc.secure.transaction.Transaction;
import com.celeral.netlet.util.Throwables;

import static com.celeral.netlet.util.Throwables.throwFormatted;

public class UploadTransaction implements Transaction
{
  static int CHUNK_SIZE = 1024 * 1024;
  private static AtomicLong transaction_id_generator = new AtomicLong();
  private final long id;
  @FieldSerializer.Bind(JavaSerializer.class)
  private final File path;
  private final int chunkSize;
  private long count;

  transient UploadTransactionData data;

  private UploadTransaction()
  {
    id = 0;
    path = null;
    chunkSize = 0;
  }

  public UploadTransaction(String path, int chunkSize) throws IOException
  {
    this.chunkSize = chunkSize <= 0 ? CHUNK_SIZE : chunkSize;

    this.id = transaction_id_generator.incrementAndGet();
    this.path = new File(path);

    if (this.path.exists()) {
      if (this.path.isFile()) {
        if (this.path.canRead()) {
          long length = this.path.length();
          this.count = length / this.chunkSize;
          if (length % this.chunkSize != 0) {
            this.count++;
          }
        }
        else {
          throw throwFormatted(IllegalArgumentException.class,
                               "Unable to read file {} to create upload transaction!",
                               this.path);
        }
      }
      else {
        throw throwFormatted(IllegalArgumentException.class,
                             "Unable to create upload transaction with non-regular file {}!",
                             this.path);
      }
    }
    else {
      throw throwFormatted(IllegalArgumentException.class,
                           "Unable to create upload transaction with non existent file {}!",
                           this.path);
    }
  }

  public UploadPayloadIterator getPayloadIterator()
  {
    return new UploadPayloadIterator();
  }

  public long getChunkSize()
  {
    return chunkSize;
  }


  public class UploadPayloadIterator implements Iterator<Payload<Transaction>>, Closeable
  {
    final FileInputStream is;
    int seq;

    public UploadPayloadIterator()
    {
      try {
        is = new FileInputStream(path);
      }
      catch (FileNotFoundException ex) {
        throw Throwables.throwFormatted(ex, RuntimeException.class,
                                        "Unable to open {} for transaction {}",
                                        path, UploadTransaction.this.getId());
      }
    }

    @Override
    public boolean hasNext()
    {
      return seq < count;
    }

    @Override
    public Payload<Transaction> next()
    {
      byte[] bytes = new byte[seq == count - 1 ? (int)(UploadTransaction.this.path.length() - (long)seq * UploadTransaction.this.chunkSize) : UploadTransaction.this.chunkSize];
      try {
        is.read(bytes);
        @SuppressWarnings("rawtypes")
        Payload payload = new UploadPayload(UploadTransaction.this.getId(), seq, bytes);
        @SuppressWarnings("unchecked")
        Payload<Transaction> retval = payload;
        return retval;
      }
      catch (IOException ex) {
        throw Throwables.throwFormatted(ex, RuntimeException.class,
                                        "Unable to read chunk {} for transaction {} from file {}",
                                        seq, UploadTransaction.this.getId(), path);
      }
      finally {
        seq++;
      }
    }

    @Override
    public void remove()
    {
      throw new UnsupportedOperationException();
    }

    @Override
    public void close() throws IOException
    {
      is.close();
    }
  }


  @Override
  public long getId()
  {
    return id;
  }

  @Override
  public long getPayloadCount()
  {
    return count;
  }

  @Override
  public boolean begin(ExecutionContext context)
  {
    try {
      File tempFile = File.createTempFile(path.getName(), null, context.getStorageRoot());
      RandomAccessFile rw = new RandomAccessFile(tempFile, "rw");
      data = new UploadTransactionData(tempFile, rw);
    }
    catch (IOException ex) {
      throw throwFormatted(ex,
                           RuntimeException.class,
                           "Unable to create a temporary file for {} in directory {}",
                           path, context.getStorageRoot());
    }

    return getPayloadCount() == 0;
  }


  @Override
  public void end(ExecutionContext context)
  {
    if (data.count == getPayloadCount()) {
      commit(context);
    }
    else {
      rollback(context);
    }
  }

  public void commit(ExecutionContext context)
  {
    try {
      data.channel.close();
    }
    catch (IOException ex) {
      throw throwFormatted(ex,
                           RuntimeException.class,
                           "Unable to close a temporary file during commit {}!",
                           data.tempFile);
    }

    File dpath = new File(context.getStorageRoot(), path.getName());
    data.tempFile.renameTo(dpath);
    logger.debug("Creating file {}", dpath);
  }

  public void rollback(ExecutionContext context)
  {
    logger.debug("Deleting file {}", data.tempFile);

    try {
      data.channel.close();
    }
    catch (IOException ex) {
      throw throwFormatted(ex,
                           RuntimeException.class,
                           "Unable to close a temporary file during rollback {}!",
                           data.tempFile);
    }
    finally {
      data.tempFile.delete();
    }
  }

  @Override
  public String toString()
  {
    return "UploadTransaction{" +
      "id=" + id +
      ", path=" + path +
      ", chunkSize=" + chunkSize +
      ", count=" + count +
      '}';
  }

  private static final Logger logger = LoggerFactory.getLogger(UploadTransaction.class);
}
