package com.celeral.netlet.rpc;

public interface Bean
{
  Object create(Class<?>[] desiredIfaces, Class<?>[] unwantedIfaces, Object... args);

  Object create(Class<?> concreteType, Object... args);

  void destroy(Object id);

  Object get(Object id);
}
