package plus.lolilo;

import sun.misc.Unsafe;
import java.lang.reflect.Field;
import java.security.Permission;
import java.security.PermissionCollection;
import java.security.ProtectionDomain;
import java.security.SecureClassLoader;
import java.util.Enumeration;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.logging.Level;


public class DomainProcessor {
    /**
     * @return Unsafe instance
     */
    private static Unsafe getUnsafe() throws Exception {
        Field field;
        (field = Unsafe.class.getDeclaredField("theUnsafe")).setAccessible(true);
        return (Unsafe) field.get(null);
    }


    /**
     * Try to trim classloader
     * @return mean saved bytes
     */
    public static int runFixes(LoliLo lolilo, SecureClassLoader loader){
        //use local variables to avoid store data in heap
        Unsafe unsafe;
        try {
            unsafe = getUnsafe();
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
        AtomicInteger count;
        runFixes(unsafe, lolilo, loader, count = new AtomicInteger());

        int coef;
        try {
            String strValue = "value";
            if(unsafe.getObject(strValue, offset(unsafe, String.class, strValue)).getClass() == char[].class)
                coef = 16;
            else
                coef = 8;
        } catch (NoSuchFieldException e) {
            throw new RuntimeException(e);
        }
        return count.get() * coef;
    }


    private static void runFixes(Unsafe unsafe, LoliLo lolilo, SecureClassLoader loader, AtomicInteger count){
        try {
            //use local variables to avoid store data in heap
            long off = offset(unsafe, SecureClassLoader.class, "pdcache");
            long nameOff = offset(unsafe, Permission.class,"name");

            try {
                ClassLoader parent = loader.getParent();

                if (parent != null && parent != loader && parent instanceof SecureClassLoader) {
                    runFixes(unsafe, lolilo, (SecureClassLoader) parent, count);
                }
            } catch (SecurityException ignored) {} catch (Throwable t) {
                lolilo.getLogger().log(Level.WARNING, "Exception on LoliLo processor: ", t);
            }
            Map<?, ProtectionDomain> domains = (Map<?, ProtectionDomain>) unsafe.getObject(loader, off);

            if (domains instanceof ConcurrentHashMap) {
                forMap(unsafe, domains, count, nameOff);
            } else {
                synchronized (domains) {
                    forMap(unsafe, domains, count, nameOff);
                }
            }
        } catch (Throwable t2){
            lolilo.getLogger().log(Level.WARNING, "Exception on LoliLo processor: ", t2);
        }
    }


    /**
     * @return offset of object field
     */
    private static long offset(Unsafe unsafe, Class<?> clazz, String name) throws NoSuchFieldException {
        return unsafe.objectFieldOffset(clazz.getDeclaredField(name));
    }


    /**
     * Trim permissions in domains
     */
    private static void forMap(Unsafe unsafe, Map<?, ProtectionDomain> domains, AtomicInteger count, long nameOff) throws NoSuchFieldException {
        domains.forEach((obj, pd) -> {
            PermissionCollection pc = pd.getPermissions();
            if (pc != null) {
                Enumeration<Permission> perms = pc.elements();
                while (perms.hasMoreElements()) {
                    Permission perm = perms.nextElement();
                    count.addAndGet(perm.getName().length());
                    unsafe.putObject(perm, nameOff, "");
                }
            }
        });
    }
}
