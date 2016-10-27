package org.graylog.plugins.dnstap;

import com.codahale.metrics.InstrumentedExecutorService;
import com.codahale.metrics.MetricRegistry;
import com.google.common.util.concurrent.ThreadFactoryBuilder;
import com.google.inject.assistedinject.Assisted;
import org.graylog2.plugin.LocalMetricRegistry;
import org.graylog2.plugin.configuration.Configuration;
import org.graylog2.plugin.configuration.ConfigurationRequest;
import org.graylog2.plugin.inputs.MessageInput;
import org.graylog2.plugin.inputs.annotations.ConfigClass;
import org.graylog2.plugin.inputs.annotations.FactoryClass;
import org.graylog2.plugin.inputs.transports.AbstractTcpTransport;
import org.graylog2.plugin.inputs.transports.NettyTransport;
import org.graylog2.plugin.inputs.transports.Transport;
import org.graylog2.plugin.inputs.util.ConnectionCounter;
import org.graylog2.plugin.inputs.util.ThroughputCounter;
import org.jboss.netty.channel.ChannelHandler;
import org.jboss.netty.buffer.ChannelBuffer;

import javax.inject.Inject;
import javax.inject.Named;
import java.util.LinkedHashMap;
import java.util.concurrent.Callable;
import java.util.concurrent.Executor;
import java.util.concurrent.Executors;
import java.util.concurrent.ThreadFactory;

import org.graylog.plugins.dnstap.FstrmFrameDecoder;

import static com.codahale.metrics.MetricRegistry.name;

public class FstrmTransport extends AbstractTcpTransport {
    @Inject
    public FstrmTransport(@Assisted Configuration configuration,
                          @Named("bossPool") Executor bossPool,
                          ThroughputCounter throughputCounter,
                          ConnectionCounter connectionCounter,
                          LocalMetricRegistry localRegistry) {
        this(configuration,
             bossPool,
             executorService("fstrm-worker", "fstrm-transport-worker-%d", localRegistry),
             throughputCounter,
             connectionCounter,
             localRegistry);
    }

    private FstrmTransport(final Configuration configuration,
                           final Executor bossPool,
                           final Executor workerPool,
                           final ThroughputCounter throughputCounter,
                           final ConnectionCounter connectionCounter,
                           final LocalMetricRegistry localRegistry) {
        super(configuration, throughputCounter, localRegistry, bossPool, workerPool, connectionCounter);
    }

    private static Executor executorService(final String executorName,
                                            final String threadNameFormat,
                                            final MetricRegistry metricRegistry) {
        final ThreadFactory threadFactory = new ThreadFactoryBuilder().setNameFormat(threadNameFormat).build();
        return new InstrumentedExecutorService(
                Executors.newCachedThreadPool(threadFactory),
                metricRegistry,
                name(FstrmTransport.class, executorName, "executor-service"));
    }

    @Override
    protected LinkedHashMap<String, Callable<? extends ChannelHandler>> getFinalChannelHandlers(MessageInput input) {
        final LinkedHashMap<String, Callable<? extends ChannelHandler>> finalChannelHandlers = super.getFinalChannelHandlers(input);
        final LinkedHashMap<String, Callable<? extends ChannelHandler>> handlers = new LinkedHashMap<>();
        handlers.put("fstrm", FstrmFrameDecoder::new);
        handlers.putAll(finalChannelHandlers);

        return handlers;
    }

    @FactoryClass
    public interface Factory extends Transport.Factory<FstrmTransport> {
        @Override
        FstrmTransport create(Configuration configuration);

        @Override
        Config getConfig();
    }

    @ConfigClass
    public static class Config extends AbstractTcpTransport.Config {
        @Override
        public ConfigurationRequest getRequestedConfiguration() {
            final ConfigurationRequest cr = super.getRequestedConfiguration();
            if (cr.containsField(NettyTransport.CK_PORT)) {
                cr.getField(NettyTransport.CK_PORT).setDefaultValue(6000);
            }
            return cr;
        }
    }
}
