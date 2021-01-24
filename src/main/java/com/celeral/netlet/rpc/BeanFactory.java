package com.celeral.netlet.rpc;

public interface BeanFactory
{
  Object create(Class<?>[] desiredIfaces, Object... args);

  Object create(Class<?> concreteType, Object... args);

  void destroy(Object id);

  Object get(Object id);

  boolean contains(Object id);
}
