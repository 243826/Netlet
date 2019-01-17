package com.celeral.netlet.rpc.secure;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.celeral.netlet.rpc.secure.transaction.Payload;
import com.celeral.netlet.rpc.secure.transaction.Transaction;
import com.celeral.netlet.rpc.secure.transaction.TransactionProcessor;

public class ConsoleTransactionProcessor implements TransactionProcessor
{
  @Override
  public void process(Transaction<?> transaction)
  {
    logger.info("received transaction {}", transaction);
  }

  @Override
  public void process(Payload<?> payload)
  {
    logger.info("received payload {}", payload);
  }

  private static final Logger logger = LoggerFactory.getLogger(ConsoleTransactionProcessor.class);
}
