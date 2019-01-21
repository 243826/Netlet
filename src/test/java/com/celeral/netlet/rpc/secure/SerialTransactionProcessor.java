package com.celeral.netlet.rpc.secure;

import java.io.File;

import org.apache.commons.lang3.SystemUtils;

import com.celeral.netlet.rpc.secure.transaction.ExecutionContext;
import com.celeral.netlet.rpc.secure.transaction.Payload;
import com.celeral.netlet.rpc.secure.transaction.Transaction;
import com.celeral.netlet.rpc.secure.transaction.TransactionProcessor;

public class SerialTransactionProcessor implements TransactionProcessor
{
  private ExecutionContext context;
  private Transaction transaction;

  @Override
  public void process(Transaction transaction)
  {
    initExecutionContext(transaction);
    if (transaction.begin(context)) {
      transaction.end(context);
    }
    else {
      this.transaction = transaction;
    }
  }

  private void initExecutionContext(final Transaction transaction)
  {
    if (this.transaction != null) {
      this.transaction.end(context);
    }

    context = new ExecutionContext()
    {
      @Override
      public long getTenantId()
      {
        return 0;
      }

      @Override
      public File getStorageRoot()
      {
        return SystemUtils.getJavaIoTmpDir();
      }
    };
  }

  @Override
  public void process(Payload<Transaction> payload)
  {
    if (payload.execute(context, transaction)) {
      transaction.end(context);
      transaction = null;
    }
  }
}
