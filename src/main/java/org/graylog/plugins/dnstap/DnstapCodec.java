package org.graylog.plugins.dnstap;

import com.google.inject.assistedinject.Assisted;
import org.graylog2.plugin.Message;
import org.graylog2.plugin.configuration.Configuration;
import org.graylog2.plugin.configuration.ConfigurationRequest;
import org.graylog2.plugin.configuration.fields.ConfigurationField;
import org.graylog2.plugin.configuration.fields.BooleanField;
import org.graylog2.plugin.inputs.annotations.Codec;
import org.graylog2.plugin.inputs.annotations.ConfigClass;
import org.graylog2.plugin.inputs.annotations.FactoryClass;
import org.graylog2.plugin.inputs.codecs.AbstractCodec;
import org.graylog2.plugin.journal.RawMessage;
import org.joda.time.DateTime;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import javax.inject.Inject;


import com.google.protobuf.InvalidProtocolBufferException;
import org.graylog.plugins.dnstap.protos.DnstapOuterClass;
// TODO: http://vlkan.com/blog/post/2015/11/27/maven-protobuf/


import org.graylog.plugins.dnstap.Helper;


@Codec(name = "dnstap", displayName = "Dnstap")
public class DnstapCodec extends AbstractCodec {
    private static final Logger Log = LoggerFactory.getLogger(DnstapCodec.class);
    public static final String CK_DO_NOT_PUT_FULL_MESSAGE = "do_not_put_full_message";

    private final boolean withoutFullMessage;

    @Inject
    public DnstapCodec(@Assisted Configuration configuration) {
        super(configuration);
        this.withoutFullMessage = configuration.getBoolean(CK_DO_NOT_PUT_FULL_MESSAGE);
    }

    @Nullable
    @Override
    public Message decode(@Nonnull final RawMessage rawMessage){
        Log.trace("Received raw message {}", rawMessage);
        return getMessage(rawMessage);
    }

    @FactoryClass
    public interface Factory extends AbstractCodec.Factory<DnstapCodec> {
        @Override
        DnstapCodec create(Configuration configuration);

        @Override
        Config getConfig();

        @Override
        Descriptor getDescriptor();
    }

    @ConfigClass
    public static class Config extends AbstractCodec.Config {
        @Override
        public ConfigurationRequest getRequestedConfiguration() {
            final ConfigurationRequest cr = super.getRequestedConfiguration();
            //
            cr.addField( new BooleanField(
                CK_DO_NOT_PUT_FULL_MESSAGE,
                "Do not put pretty print",
                false,
                "Do not put full message with pretty print of DNS packet"
            ));
            //
            return cr;
        }
    }

    public static class Descriptor extends AbstractCodec.Descriptor {
        @Inject
        public Descriptor() {
            super(DnstapCodec.class.getAnnotation(Codec.class).displayName());
        }
    }


    private Message getMessage(final RawMessage rawMessage) {
        final byte[] payload = rawMessage.getPayload();
        final DnstapOuterClass.Dnstap dnstap;
        try {
            dnstap = DnstapOuterClass.Dnstap.parseFrom(payload);
        }
        catch (InvalidProtocolBufferException e) {
            return null;
        }
        switch (dnstap.getType()) {
            case MESSAGE:
                return parseMessage(dnstap.getMessage(), rawMessage);
            default:
                return null;
        }
    }

    private Message parseMessage(final DnstapOuterClass.Message message,
                                 final RawMessage rawMessage) {
        // Metadata from Dnstap
        final DateTime msgTimestamp  = Helper.getDateTime(message, rawMessage);
        final String   msgHostname   = Helper.getHostname(message, rawMessage);
        final long     msgExecTime   = Helper.getExecTimeNsec(message);
        final String   msgType       = message.getType().toString();
        final String   msgSockFamily = message.getSocketFamily().toString();
        final String   msgSockProto  = message.getSocketProtocol().toString();
        final String   msgQueryAddr  = Helper.prepareIpAddress(message.getQueryAddress());
        final int      msgQueryPort  = message.getQueryPort();
        final String   msgRespAddr   = Helper.prepareIpAddress(message.getResponseAddress());
        final int      msgRespPort   = message.getResponsePort();
        // Dns packet
        final Helper.DNSMessage dns = new Helper.DNSMessage(message);
        if (dns == null || ! dns.isValid()) {
            return null;
        }
        //
        final String msgMessage = getShortMessage(msgQueryAddr, dns);
        //
        final Message msg = new Message(msgMessage, msgHostname, msgTimestamp);
        if (!withoutFullMessage) {
            msg.addField("full_message", dns.getFullMessage());
        }
        if (msgExecTime >= 0) {
            msg.addField("dnstap_exec_time", msgExecTime);
        }
        msg.addField("dnstap_type"       , msgType);
        msg.addField("dnstap_sock_family", msgSockFamily);
        msg.addField("dnstap_sock_proto" , msgSockProto);
        if (msgQueryAddr != null) {
            msg.addField("dnstap_query_addr", msgQueryAddr);
            msg.addField("dnstap_query_port", msgQueryPort);
        }
        if (msgRespAddr != null) {
            msg.addField("dnstap_resp_addr", msgRespAddr);
            msg.addField("dnstap_resp_port", msgRespPort);
        }
        msg.addField("dnstap_size"       , dns.size);
        msg.addField("dnstap_id"         , dns.id);
        msg.addField("dnstap_flags"      , dns.flags);
        msg.addField("dnstap_rcode"      , dns.rcode);
        msg.addField("dnstap_opcode"     , dns.opcode);
        //
        msg.addField("dnstap_qname"      , dns.questName);
        msg.addField("dnstap_qtype"      , dns.questType);
        msg.addField("dnstap_qdclass"    , dns.questDClass);
        //
        msg.addField("dnstap_num_questions"  , dns.numQuestions);
        msg.addField("dnstap_num_answers"    , dns.numAnswers);
        msg.addField("dnstap_num_authorities", dns.numAuthorities);
        msg.addField("dnstap_num_additionals", dns.numAdditionals);
        msg.addField("dnstap_num_zones"      , dns.numZones);
        msg.addField("dnstap_num_prereqs"    , dns.numPrereqs);
        msg.addField("dnstap_num_updates"    , dns.numUpdates);
        //
        Log.trace("Dnstap out message {}", msg);
        return msg;
    }


    private String getShortMessage(final String queryAddr,
                                   final Helper.DNSMessage dns) {
        //
        // 10.76.151.44 -> google.ru. (IN, A)
        // 10.76.151.44 <- google.ru. (IN, A) [173.194.44.95 173.194.44.87 173.194.44.88]
        final String question = dns.firstQuestion;
        final String direction;
        final String answer;
        switch (dns.getType()) {
            case QUERY:
                direction = "->";
                answer  = "";
                break;
            case RESPONSE:
                direction = "<-";
                if (dns.numAnswers > 0) {
                    answer = " [" + String.join(" ", dns.listOfAnswersData) + "]";
                }
                else {
                    answer = " []";
                }
                break;
            default:
                direction = "";
                answer = "";
        }
        return queryAddr + " " + direction + " " + question + answer;
    }

}
