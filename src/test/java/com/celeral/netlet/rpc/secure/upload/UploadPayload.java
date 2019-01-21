package com.celeral.netlet.rpc.secure.upload;

import java.io.IOException;
import java.io.RandomAccessFile;

import com.celeral.netlet.rpc.secure.transaction.ExecutionContext;
import com.celeral.netlet.rpc.secure.transaction.Payload;
import com.celeral.netlet.util.Throwables;

public class UploadPayload implements Payload<UploadTransaction>
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
      "data=" + data.length +
      ", transactionId=" + transactionId +
      ", sequenceId=" + sequenceId +
      '}';
  }

  @Override
  public boolean execute(ExecutionContext context, UploadTransaction transaction)
  {
    UploadTransactionData data = transaction.data;
    RandomAccessFile channel = data.channel;
    try {
      channel.seek(transaction.getChunkSize() * sequenceId);
      channel.write(this.data);
    }
    catch (IOException ex) {
      throw Throwables.throwFormatted(ex,
                                      RuntimeException.class,
                                      "Unable to write chunk: {} in file {}!",
                                      this, data.tempFile);
    }

    return transaction.getPayloadCount() == ++data.count;
  }

}
