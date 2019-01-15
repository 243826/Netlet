package com.celeral.netlet.rpc.secure.upload;

import java.io.IOException;
import java.io.RandomAccessFile;

import com.celeral.netlet.rpc.secure.transaction.ExecutionContext;
import com.celeral.netlet.rpc.secure.transaction.Payload;
import com.celeral.netlet.rpc.secure.transaction.Transaction;
import com.celeral.netlet.util.Throwables;

public class UploadPayload implements Payload<UploadTransactionData>
{
  byte[] data;
  long transactionId;
  int sequenceId;

  private UploadPayload()
  {
    /* jlto */
  }
  public UploadPayload(long transactionId, int sequenceId, byte[] data)
  {
    this.transactionId = transactionId;
    this.sequenceId = sequenceId;
    this.data = data;
  }

  @Override
  public long getTransactionId()
  {
    return transactionId;
  }

  @Override
  public int getSequenceId()
  {
    return sequenceId;
  }

  @Override
  public String toString()
  {
    return "UploadPayload{" +
      "data=" +data.length +
      ", transactionId=" + transactionId +
      ", sequenceId=" + sequenceId +
      '}';
  }

  @Override
  public void execute(ExecutionContext<UploadTransactionData> context)
  {
    Transaction<?> transaction = context.getTransaction();
    if (transaction instanceof UploadTransaction) {
      UploadTransaction ut = (UploadTransaction) transaction;
      RandomAccessFile channel = context.data().channel;
      try {
        channel.seek(ut.getChunkSize() * sequenceId);
        channel.write(this.data);
      }
      catch (IOException ex) {
        throw Throwables.throwFormatted(ex,
                                        RuntimeException.class,
                                        "Unable to write chunk: {} in file {}!",
                                        this, context.data().tempFile);
      }
    }

  }

}
