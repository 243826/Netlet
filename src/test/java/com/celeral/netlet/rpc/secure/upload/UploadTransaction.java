package com.celeral.netlet.rpc.secure.upload;

import com.celeral.netlet.rpc.secure.ExecutionContext;
import com.celeral.netlet.rpc.secure.Payload;
import com.celeral.netlet.rpc.secure.Transaction;
import com.celeral.netlet.util.Throwables;
import com.esotericsoftware.kryo.serializers.FieldSerializer;
import com.esotericsoftware.kryo.serializers.JavaSerializer;

import java.io.*;
import java.util.Iterator;
import java.util.concurrent.atomic.AtomicLong;

import static com.celeral.netlet.util.Throwables.throwFormatted;

public class UploadTransaction implements Transaction<UploadTransactionData>
{
  static int CHUNK_SIZE = 1024 * 1024;
  private static AtomicLong transaction_id_generator = new AtomicLong();
  private final long id;
  @FieldSerializer.Bind(JavaSerializer.class)
  private final File path;
  private final int chunkSize;
  private long count;

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


  public class UploadPayloadIterator implements Iterator<UploadPayload>, Closeable
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
    public UploadPayload next()
    {
      byte[] bytes = new byte[seq == count - 1 ? (int)(UploadTransaction.this.path.length() - (long)seq * UploadTransaction.this.chunkSize) : UploadTransaction.this.chunkSize];
      try {
        is.read(bytes);
        return new UploadPayload(UploadTransaction.this.getId(), seq, bytes);
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
  public void begin(ExecutionContext<UploadTransactionData> context)
  {
    try {
      File tempFile = File.createTempFile(path.getName(), null, context.getStorageRoot());
      RandomAccessFile rw = new RandomAccessFile(tempFile, "rw");
      context.data(new UploadTransactionData(tempFile, rw));
    }
    catch (IOException ex) {
      throw throwFormatted(ex,
                           RuntimeException.class,
                           "Unable to create a temporary file for {} in directory {}",
                           path, context.getStorageRoot());
    }
  }


  @Override
  public void end(ExecutionContext<UploadTransactionData> context)
  {
    commit(context);
  }

  public void commit(ExecutionContext<UploadTransactionData> context)
  {
    UploadTransactionData data = context.data();
    try {
      data.channel.close();
    }
    catch (IOException ex) {
      throw throwFormatted(ex,
                           RuntimeException.class,
                           "Unable to close a temporary file during commit {}!",
                           data.tempFile);
    }

    data.tempFile.renameTo(path);
  }

  public void rollback(ExecutionContext<UploadTransactionData> context)
  {
    UploadTransactionData data = context.data();

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
}
