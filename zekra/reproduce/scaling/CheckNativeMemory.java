import java.lang.reflect.*;
import java.util.Arrays;
import backend.auxTypes.*;
import backend.config.Config;

/** Checks metadata without constructing a circuit; use patched and original jars as controls. */
public final class CheckNativeMemory {
  public static void main(String[] args) throws Exception {
    Class<?> unsafeClass = Class.forName("sun.misc.Unsafe");
    Field f = unsafeClass.getDeclaredField("theUnsafe"); f.setAccessible(true);
    Object unsafe = f.get(null);
    Object memory = unsafeClass.getMethod("allocateInstance", Class.class).invoke(unsafe, SmartMemory.class);
    Field type = SmartMemory.class.getDeclaredField("typeClass"); type.setAccessible(true); type.set(memory, FieldElement.class);
    Field params = SmartMemory.class.getDeclaredField("typeArgs"); params.setAccessible(true);
    params.set(memory, new Object[]{Config.getFiniteFieldModulus().toString()});
    Method method = SmartMemory.class.getDeclaredMethod("getElementSize"); method.setAccessible(true);
    int[] result = (int[])method.invoke(memory);
    System.out.println("native_field_limb_bitwidths=" + Arrays.toString(result));
    if (args.length > 0 && args[0].equals("fixed") && !Arrays.equals(result, new int[]{254}))
      throw new AssertionError("native field must occupy one full-width limb");
    if (args.length > 0 && args[0].equals("fixed")) {
      Method width = SmartMemory.class.getDeclaredMethod("zkcfaNativeMemoryChunkWidth",SmartMemory.class);
      width.setAccessible(true);
      if (!width.invoke(null,memory).equals(254)) throw new AssertionError("native write width");
      type.set(memory,UnsignedInteger.class); params.set(memory,new Object[]{"96"});
      if (!width.invoke(null,memory).equals(32)) throw new AssertionError("unsigned fallback changed");
      type.set(memory,FieldElement.class); params.set(memory,new Object[]{"2305843009213693951"});
      if (!width.invoke(null,memory).equals(32)) throw new AssertionError("non-native field fallback changed");
      System.out.println("native_write_width=254; unsigned_and_non_native_field_fallback_width=32");
    }
  }
}
