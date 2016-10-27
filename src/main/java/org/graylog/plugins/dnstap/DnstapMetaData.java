package org.graylog.plugins.dnstap;

import org.graylog2.plugin.PluginMetaData;
import org.graylog2.plugin.ServerStatus;
import org.graylog2.plugin.Version;

import java.net.URI;
import java.util.Collections;
import java.util.Set;

/**
 * Implement the PluginMetaData interface here.
 */
public class DnstapMetaData implements PluginMetaData {
    private static final String PLUGIN_PROPERTIES = "org.graylog.plugins.dnstap.graylog-plugin-dnstap/graylog-plugin.properties";

    @Override
    public String getUniqueId() {
        return "org.graylog.plugins.dnstap.DnstapPlugin";
    }

    @Override
    public String getName() {
        return "Dnstap Plugin";
    }

    @Override
    public String getAuthor() {
        return "Sergey I. Yarkin <sega.yarkin@gmail.com>";
    }

    @Override
    public URI getURL() {
        return URI.create("https://github.com/sega-yarkin/graylog-plugin-dnstap");
    }

    @Override
    public Version getVersion() {
        return Version.fromPluginProperties(getClass(), PLUGIN_PROPERTIES, "version", Version.from(0, 0, 0, "unknown"));
    }

    @Override
    public String getDescription() {
        return "Provides Dnstap inputs";
    }

    @Override
    public Version getRequiredVersion() {
        return Version.fromPluginProperties(getClass(), PLUGIN_PROPERTIES, "graylog.version", Version.from(0, 0, 0, "unknown"));
    }

    @Override
    public Set<ServerStatus.Capability> getRequiredCapabilities() {
        return Collections.emptySet();
    }
}
