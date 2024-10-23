package plus.lolilo;

import org.bukkit.plugin.Plugin;
import org.bukkit.plugin.java.JavaPlugin;
import sun.misc.Unsafe;
import java.lang.reflect.Field;
import java.security.Permission;
import java.security.PermissionCollection;
import java.security.ProtectionDomain;
import java.security.SecureClassLoader;
import java.util.Enumeration;
import java.util.IdentityHashMap;
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
     * Run trimmer for all known classloaders
     * @return mean saved bytes
     */
    public static int runFixes(LoliLo lolilo, SecureClassLoader loader) throws Exception{
        //use local variables to avoid store data in heap
        Unsafe unsafe;
        try {
            unsafe = getUnsafe();
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
        IdentityHashMap<SecureClassLoader,Object> loaders;

        AtomicInteger count;
        runFixesRec(unsafe, lolilo, loader, count = new AtomicInteger(), loaders = new IdentityHashMap<>());

        long loaderOff = offset(unsafe, JavaPlugin.class, "classLoader");

        for (Plugin plug:lolilo.getServer().getPluginManager().getPlugins()){
            if(plug instanceof JavaPlugin){
                ClassLoader loader0 = (ClassLoader)unsafe.getObject(plug, loaderOff);
                if(loader0 instanceof SecureClassLoader){
                    runFixesRec(unsafe, lolilo, loader, count, loaders);
                }
            }
        }

        int coef;
        String strValue = "value";
        if(unsafe.getObject(strValue, offset(unsafe, String.class, strValue)).getClass() == char[].class)
            coef = 16;
        else
            coef = 8;
        return count.get() * coef;
    }


    /**
     * Run fixes for classloader and parents
     */
    private static void runFixesRec(Unsafe unsafe, LoliLo lolilo, SecureClassLoader loader, AtomicInteger count, IdentityHashMap<SecureClassLoader,Object> loaders){
        if(loaders.containsKey(loader))return;
        loaders.put(loader,loader);
        runFixes(unsafe, lolilo, loader, count);

        ClassLoader parent = loader.getParent();
        while (parent != null){
            if(parent instanceof SecureClassLoader){
                if(!loaders.containsKey(loader)) {
                    loaders.put(loader, loader);
                    runFixes(unsafe, lolilo, (SecureClassLoader) parent, count);
                }
            }
            ClassLoader next = parent.getParent();
            if(next != parent)parent = next;
        }
    }


    /**
     * Run fixes for classloader
     */
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
                    count.addAndGet(perm.getName().length()+12); //12 - sum of ref bytes len
                    unsafe.putObject(perm, nameOff, "");
                }
            }
        });
    }
}
