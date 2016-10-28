package org.graylog.plugins.dnstap;

import org.graylog2.plugin.journal.RawMessage;
import org.graylog2.plugin.ResolvableInetSocketAddress;
import org.joda.time.DateTime;
import java.net.InetAddress;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import java.util.ArrayList;


import org.xbill.DNS.Message;
import org.xbill.DNS.Header;
import org.xbill.DNS.Section;
import org.xbill.DNS.Record;
import org.xbill.DNS.DClass;
import org.xbill.DNS.Type;
import org.xbill.DNS.Opcode;
import org.xbill.DNS.Rcode;
import org.xbill.DNS.Name;

import com.google.protobuf.ByteString;
import com.google.protobuf.InvalidProtocolBufferException;
import org.graylog.plugins.dnstap.protos.DnstapOuterClass;

public class Helper {
    private static final Logger Log = LoggerFactory.getLogger("DnstapHelper");

    public enum DnsFrameType {
        UNKNOWN,
        QUERY,
        RESPONSE;

        public static DnsFrameType get(final DnstapOuterClass.Message message) {
            switch (message.getType()) {
                case AUTH_QUERY:
                case RESOLVER_QUERY:
                case CLIENT_QUERY:
                    return QUERY;
                case AUTH_RESPONSE:
                case RESOLVER_RESPONSE:
                case CLIENT_RESPONSE:
                    return RESPONSE;
            }
            return UNKNOWN;
        }
    }


    public static DateTime getDateTime(final DnstapOuterClass.Message message,
                                       final RawMessage rawMessage) {
        long sec  = 0;
        int  nsec = 0;
        final DateTime result;
        switch (DnsFrameType.get(message)) {
            case QUERY:
                sec  = message.getQueryTimeSec();
                nsec = message.getQueryTimeNsec();
                break;
            case RESPONSE:
                sec  = message.getResponseTimeSec();
                nsec = message.getResponseTimeNsec();
                break;
        }
        if (sec > 0) {
            final long instant = (sec*1000) + Math.round(nsec/1e6);
            result = new DateTime(instant);
        }
        else {
            result = rawMessage.getTimestamp();
        }
        return result;
    }


    public static String getHostname(final DnstapOuterClass.Message message,
                                     final RawMessage rawMessage) {
        final ResolvableInetSocketAddress addr = rawMessage.getRemoteAddress();
        String hostname = "unknown";
        if (addr != null) {
            hostname = rawMessage.getRemoteAddress().getInetSocketAddress().getHostName();
        }
        return hostname;
    }


    public static long getExecTimeNsec(final DnstapOuterClass.Message message) {
        final long NANO_IN_SECOND = 1_000_000_000;
        long execTime = -1;
        switch (DnsFrameType.get(message)) {
            case RESPONSE:
                final long querySec  = message.getQueryTimeSec();
                final int  queryNsec = message.getQueryTimeNsec();
                final long respSec   = message.getResponseTimeSec();
                final int  respNsec  = message.getResponseTimeNsec();
                if (querySec>0 && respSec>0) {
                    final long sec  = respSec  - querySec;
                    final int  nsec = respNsec - queryNsec;
                    execTime = sec*NANO_IN_SECOND + nsec;
                }
                break;
        }
        return execTime;
    }


    public static String prepareIpAddress(final ByteString addr) {
        String result = null;
        if (addr != null) {
            try {
                final byte[] bytes = addr.toByteArray();
                final InetAddress address = InetAddress.getByAddress(bytes);
                result = address.getHostAddress();
            }
            catch (Exception e) {}
        }
        return result;
    }


    public static class DNSMessage {
        public Message      _dns  = null;
        public DnsFrameType _type = DnsFrameType.UNKNOWN;
        // Header
        public int          size = 0;
        public int          id   = -1;
        public String       opcode;
        public String       rcode;
        public String       flags;
        public int          numQuestions   = 0;
        public int          numAnswers     = 0;
        public int          numAuthorities = 0;
        public int          numAdditionals = 0;
        public int          numZones       = 0;
        public int          numPrereqs     = 0;
        public int          numUpdates     = 0;
        // Data
        public String            questName;
        public String            questType;
        public String            questDClass;
        public String            firstQuestion;
        public ArrayList<String> listOfAnswersData;


        public DNSMessage(final DnstapOuterClass.Message message) {
            parseDnsWire(message);
            if (!isValid()) {
                return;
            }
            size   = _dns.numBytes();
            final Header header = _dns.getHeader();
            id     = header.getID();
            opcode = Opcode.string(header.getOpcode());
            rcode  = Rcode.string(header.getRcode());
            flags  = header.printFlags();
            numQuestions   = header.getCount(Section.QUESTION);
            numAnswers     = header.getCount(Section.ANSWER);
            numAuthorities = header.getCount(Section.AUTHORITY);
            numAdditionals = header.getCount(Section.ADDITIONAL);
            numZones       = header.getCount(Section.ZONE);
            numPrereqs     = header.getCount(Section.PREREQ);
            numUpdates     = header.getCount(Section.UPDATE);
            //
            fillFirstQuestion();
            listOfAnswersData = getAnswersDataList();
        }

        public boolean isValid() {
            return (_type != null);
        }

        public DnsFrameType getType() {
            return _type;
        }

        public String getFullMessage() {
            return _dns.toString();
        }

        private void parseDnsWire(final DnstapOuterClass.Message message) {
            final ByteString wire;
            _type = DnsFrameType.get(message);
            switch (_type) {
                case QUERY:
                    wire = message.getQueryMessage();
                    break;
                case RESPONSE:
                    wire = message.getResponseMessage();
                    break;
                default:
                    wire = null;
            }
            if (wire != null) {
                final byte[] bytes = wire.toByteArray();
                try {
                    _dns = new Message(bytes);
                }
                catch (Exception e) {
                    Log.error("Cannot parse wire dns packet: {}", bytes);
                }
            }
        }

        private void fillFirstQuestion() {
            final Record q = _dns.getQuestion();
            questName = q.getName().toString();
            questType = Type.string(q.getType());
            questDClass = DClass.string(q.getDClass());
            firstQuestion = questName + " (" + questDClass + ", " + questType + ")";
        }

        private ArrayList<String> getAnswersDataList() {
            Record[] list = _dns.getSectionArray(Section.ANSWER);
            ArrayList<String> result = new ArrayList<>(list.length);
            for (int i=0; i<list.length; i++) {
                switch (list[i].getType()) {
                    case Type.A:
                        addAnswerToList(result, ((org.xbill.DNS.ARecord)list[i]).getAddress());
                        break;
                    case Type.AAAA:
                        addAnswerToList(result, ((org.xbill.DNS.AAAARecord)list[i]).getAddress());
                        break;
                    case Type.MX:
                        addAnswerToList(result, (org.xbill.DNS.MXRecord)list[i]);
                        break;
                    case Type.CNAME:
                        addAnswerToList(result, ((org.xbill.DNS.CNAMERecord)list[i]).getTarget());
                        break;
                    case Type.NS:
                        addAnswerToList(result, ((org.xbill.DNS.NSRecord)list[i]).getTarget());
                        break;
                    case Type.SRV:
                        addAnswerToList(result, ((org.xbill.DNS.SRVRecord)list[i]).getTarget());
                        break;
                    case Type.PTR:
                        addAnswerToList(result, ((org.xbill.DNS.PTRRecord)list[i]).getTarget());
                        break;
                    case Type.SOA:
                        addAnswerToList(result, (org.xbill.DNS.SOARecord)list[i]);
                }
            }
            return result;
        }

        private void addAnswerToList(final ArrayList<String> list,
                                     final InetAddress addr) {
            if (addr != null) {
                list.add(addr.getHostAddress());
            }
        }

        private void addAnswerToList(final ArrayList<String> list,
                                     final Name name) {
            if (name != null) {
                list.add(name.toString(true));
            }
        }

        private void addAnswerToList(final ArrayList<String> list,
                                     final org.xbill.DNS.MXRecord mx) {
            final Name name = mx.getTarget();
            final int  pri  = mx.getPriority();
            if (name != null) {
                list.add(name.toString(true) + "("+pri+")");
            }
        }

        private void addAnswerToList(final ArrayList<String> list,
                                     final org.xbill.DNS.SOARecord soa) {
            final Name host = soa.getHost();
            if (host != null) {
                final Name admin = soa.getAdmin();
                final String answer = "(" + host.toString(true)
                    + " " + ((admin != null) ? admin.toString(true) : "")
                    + " " + soa.getSerial()
                    + " " + soa.getRefresh()
                    + " " + soa.getRetry()
                    + " " + soa.getExpire()
                    + " " + soa.getMinimum() +")";
                list.add(answer);
            }
        }

    }



}
