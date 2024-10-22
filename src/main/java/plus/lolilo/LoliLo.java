package plus.lolilo;

import org.bukkit.Bukkit;
import org.bukkit.plugin.java.JavaPlugin;
import java.security.SecureClassLoader;


/**
 * LoliLo - plugin to trmim SecureClassLoaders using Unsafe
 * <p>
 * {@code LoliLo DONT USE ANY CONFIGURATIONS AND AUTOMATICALLY DISABLED TO PRESERVE MEMORY}
 * <p>
 * {@code To configure delay use -Dlolilo.delay=80 (in ticks) system property}
 *
 * @author HomaPlus
 */
public final class LoliLo extends JavaPlugin {
    @Override
    public void onEnable() {
        ClassLoader loader = this.getClassLoader();
        int delay = 80;
        try {
            String rawDelay = System.getProperty("lolilo.delay");
            if(rawDelay != null) delay = Integer.valueOf(rawDelay);
        } catch (Exception ignored){}

        if(loader instanceof SecureClassLoader) {
            Bukkit.getScheduler().runTaskLaterAsynchronously(this, () -> {
                ClassLoader curLoader = LoliLo.this.getClassLoader();
                if(curLoader instanceof SecureClassLoader) {
                    int count = DomainProcessor.runFixes(LoliLo.this, (SecureClassLoader) curLoader);
                    getLogger().info("Lolilo saved "+count+"bytes!");
                } else {
                    getLogger().warning("Lolilo classloader changed!");
                    getLogger().warning("Lolilo can`t trim loader ["+curLoader.getClass()+"]");
                }
                getPluginLoader().disablePlugin(LoliLo.this);
            }, delay);
        } else {
            getLogger().warning("Lolilo can`t trim loader ["+loader.getClass()+"]");
            getPluginLoader().disablePlugin(this);
        }
    }
}