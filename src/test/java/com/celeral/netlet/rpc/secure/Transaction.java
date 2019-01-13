package com.celeral.netlet.rpc.secure;

public interface Transaction<T>
{
  long getId();
  long getPayloadCount();
  void begin(ExecutionContext<T> context);
  void end(ExecutionContext<T> context);
}
