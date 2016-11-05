package org.graylog.plugins.dnstap;

import com.google.common.io.ByteStreams;
import org.jboss.netty.buffer.ChannelBuffer;
import org.jboss.netty.buffer.ChannelBuffers;
import org.jboss.netty.channel.Channel;
import org.jboss.netty.channel.ChannelHandlerContext;
import org.jboss.netty.handler.codec.frame.FrameDecoder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import java.io.IOException;
import java.io.InputStream;

/**
    https://github.com/farsightsec/fstrm/


    FSTRM Frame:
        +---------+---------+
        |  Size   |  Data   |
        +---------+---------+
        | 4 Bytes | N Bytes |
        +---------+---------+

        Size - Frame data size
        Data - Frame data

    FSTRM Control Frame (Size = 0):
        +----------+---------+---------+---------+---------+
        | 00000000 |  CSize  |  CType  |  FType  |  FData  |
        +----------+---------+---------+---------+---------+
        |  4 Bytes | 4 Bytes | 4 Bytes | 4 Bytes | N Bytes |
        +----------+---------+---------+---------+---------+

        CSize - Control frame size
        CType - Control frame type
        FType - Field type
        FData - Field data (e.g. content type)

*/

public class FstrmFrameDecoder extends FrameDecoder {
    private static final Logger Log = LoggerFactory.getLogger(FstrmFrameDecoder.class);

    private static final int CONTROL_FRAME_MARKER = 0x00000000;
    private static final int CONTROL_FRAME_LENGTH_MAX = 512;
    private static final int CONTROL_FIELD_CONTENT_TYPE_LENGTH_MAX = 256;

    private static final int FSTRM_CONTROL_ACCEPT = 0x01;
    private static final int FSTRM_CONTROL_START  = 0x02;
    private static final int FSTRM_CONTROL_STOP   = 0x03;
    private static final int FSTRM_CONTROL_READY  = 0x04;
    private static final int FSTRM_CONTROL_FINISH = 0x05;

    private int frameSize;

    public FstrmFrameDecoder() {
        super(true);
    }

    @Override
    protected
    ChannelBuffer decode(final ChannelHandlerContext ctx,
                         final Channel channel,
                         final ChannelBuffer buffer) throws Exception {
        // We need at least 4 bytes
        if (buffer.readableBytes() < 4) {
            return null;
        }
        buffer.markReaderIndex();
        // Read next frame size
        final int frameSize = (int) buffer.readUnsignedInt();
        Log.trace("Received frame size {}", frameSize);
        // Have we got a control frame?
        if (frameSize == CONTROL_FRAME_MARKER) {
            final boolean enoughBytes = handleControlFrame(channel, buffer);
            if (! enoughBytes) {
                buffer.resetReaderIndex();
            }
            return null;
        }
        // The buffer has not enough data
        if (buffer.readableBytes() < frameSize) {
            buffer.resetReaderIndex();
            return null;
        }
        else {
            final ChannelBuffer payload = buffer.readSlice(frameSize);
            Log.trace("Received data frame");
            return payload;
        }
    }


    private boolean handleControlFrame(final Channel channel,
                                     final ChannelBuffer buffer) throws Exception {
        // We need at least 4 bytes
        if (buffer.readableBytes() < 4) {
            return false;
        }
        final int controlSize = (int) buffer.readUnsignedInt();
        Log.trace("Received control frame with size {}", controlSize);
        if (controlSize > CONTROL_FRAME_LENGTH_MAX) {
            throw new Exception("Too big control frame size");
        }
        if (buffer.readableBytes() < controlSize) {
            return false;
        }
        final int controlType = (int) buffer.readUnsignedInt();
        Log.trace("Received control frame #{}", controlType);
        final int payloadSize = controlSize - 4;
        byte[] payload = new byte[payloadSize];
        buffer.readBytes(payload, 0, payloadSize);
        //
        switch (controlType) {
            case FSTRM_CONTROL_START:
            case FSTRM_CONTROL_STOP:
                break;
            case FSTRM_CONTROL_READY:
                sendAccept(channel, payload, payloadSize);
                break;
            case FSTRM_CONTROL_ACCEPT:
            case FSTRM_CONTROL_FINISH:
                break;
            default:
                throw new Exception("Unknown control frame type");
        }
        //
        return true;
    }

    private void sendAccept(final Channel channel,
                            final byte[] payload,
                            final int payloadSize) throws IOException {
        final int controlSize = 4 + payloadSize;
        final int bufferSize  = 4 + 4 + controlSize;
        final ChannelBuffer buffer = ChannelBuffers.buffer(bufferSize);
        buffer.writeInt(CONTROL_FRAME_MARKER);
        buffer.writeInt(controlSize);
        buffer.writeInt(FSTRM_CONTROL_ACCEPT);
        buffer.writeBytes(payload, 0, payloadSize);
        //
        Log.trace("Sending Accept on channel {}", channel);
        channel.write(buffer);
    }

}
