package org.graylog.plugins.dnstap;

import com.codahale.metrics.MetricRegistry;
import javax.inject.Inject;
import com.google.inject.assistedinject.Assisted;
import com.google.inject.assistedinject.AssistedInject;
import org.graylog2.plugin.LocalMetricRegistry;
import org.graylog2.plugin.ServerStatus;
import org.graylog2.plugin.configuration.Configuration;
import org.graylog2.plugin.inputs.MessageInput;
import org.graylog2.plugin.inputs.annotations.FactoryClass;

import org.graylog.plugins.dnstap.FstrmTransport;
import org.graylog.plugins.dnstap.DnstapCodec;


public class DnstapFstrmInput extends MessageInput {
    private static final String NAME = "Dnstap Fstrm";

    @AssistedInject
    public DnstapFstrmInput(MetricRegistry metricRegistry,
                            @Assisted Configuration configuration,
                            FstrmTransport.Factory transportFactory,
                            DnstapCodec.Factory codecFactory,
                            LocalMetricRegistry localRegistry,
                            Config config,
                            Descriptor descriptor,
                            ServerStatus serverStatus) {
        super(metricRegistry, configuration, transportFactory.create(configuration),
              localRegistry, codecFactory.create(configuration),
              config, descriptor, serverStatus);
    }

    @FactoryClass
    public interface Factory extends MessageInput.Factory<DnstapFstrmInput> {
        @Override
        DnstapFstrmInput create(Configuration configuration);

        @Override
        Config getConfig();

        @Override
        Descriptor getDescriptor();
    }

    public static class Descriptor extends MessageInput.Descriptor {
        @Inject
        public Descriptor() {
            super(NAME, false, "");
        }
    }

    public static class Config extends MessageInput.Config {
        @Inject
        public Config(FstrmTransport.Factory transport, DnstapCodec.Factory codec) {
            super(transport.getConfig(), codec.getConfig());
        }
    }

}
