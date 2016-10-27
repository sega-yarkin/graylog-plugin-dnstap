package org.graylog.plugins.dnstap;

import org.graylog2.plugin.PluginConfigBean;
import org.graylog2.plugin.PluginModule;

import java.util.Collections;
import java.util.Set;

import org.graylog.plugins.dnstap.FstrmTransport;
import org.graylog.plugins.dnstap.DnstapFstrmInput;
import org.graylog.plugins.dnstap.DnstapCodec;



public class DnstapModule extends PluginModule {
    @Override
    public Set<? extends PluginConfigBean> getConfigBeans() {
        return Collections.emptySet();
    }

    @Override
    protected void configure() {
         addTransport("fstrm", FstrmTransport.class);
         addCodec("dnstap", DnstapCodec.class);
         addMessageInput(DnstapFstrmInput.class);
    }
}
