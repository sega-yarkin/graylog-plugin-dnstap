package org.graylog.plugins.dnstap;

import com.google.common.io.ByteStreams;
import org.jboss.netty.buffer.ChannelBuffer;
import org.jboss.netty.buffer.ChannelBuffers;
import org.jboss.netty.channel.Channel;
import org.jboss.netty.channel.ChannelHandlerContext;
import org.jboss.netty.handler.codec.replay.ReplayingDecoder;
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

public class FstrmFrameDecoder extends ReplayingDecoder<FstrmFrameDecoder.DecodingState> {
    private static final Logger Log = LoggerFactory.getLogger(FstrmFrameDecoder.class);

    private static final int CONTROL_FRAME_MARKER = 0x00000000;
    private static final int CONTROL_FRAME_LENGTH_MAX = 512;
    private static final int CONTROL_FIELD_CONTENT_TYPE_LENGTH_MAX = 256;

    private static final int FSTRM_CONTROL_ACCEPT = 0x01;
    private static final int FSTRM_CONTROL_START  = 0x02;
    private static final int FSTRM_CONTROL_STOP   = 0x03;
    private static final int FSTRM_CONTROL_READY  = 0x04;
    private static final int FSTRM_CONTROL_FINISH = 0x05;

    enum DecodingState {
        FRAME_SIZE,
        FRAME_DATA,
        FRAME_CONTROL
    }

    private int frameSize;

    public FstrmFrameDecoder() {
        super(DecodingState.FRAME_SIZE, true);
    }

    @Override
    protected
    ChannelBuffer decode(final ChannelHandlerContext ctx,
                         final Channel channel,
                         final ChannelBuffer buffer,
                         final DecodingState state) throws Exception {
        switch (state) {
            case FRAME_SIZE:
                return readFrameSize(channel, buffer);
            case FRAME_CONTROL:
                return handleControlFrame(channel, buffer);
            case FRAME_DATA:
                return handleDataFrame(channel, buffer);
        }
        return null;
    }


    private
    ChannelBuffer readFrameSize(final Channel channel,
                                final ChannelBuffer buffer) {
        this.frameSize = (int) buffer.readUnsignedInt();
        Log.trace("Received frame size {}", this.frameSize);
        if (this.frameSize == CONTROL_FRAME_MARKER) {
            checkpoint(DecodingState.FRAME_CONTROL);
        }
        else {
            checkpoint(DecodingState.FRAME_DATA);
        }
        return null;
    }

    private
    ChannelBuffer handleDataFrame(final Channel channel,
                                  final ChannelBuffer buffer) throws Exception {
        if (this.frameSize < 1) {
            throw new Exception("Invalid payload size");
        }

        final ChannelBuffer payload = buffer.readSlice(this.frameSize);
        Log.trace("Received data frame");
        checkpoint(DecodingState.FRAME_SIZE);
        return payload;
    }

    private
    ChannelBuffer handleControlFrame(final Channel channel,
                                     final ChannelBuffer buffer) throws Exception {
        final int controlSize = (int) buffer.readUnsignedInt();
        Log.trace("Received control frame with size {}", controlSize);
        if (controlSize > CONTROL_FRAME_LENGTH_MAX) {
            throw new Exception("Too big control frame size");
        }
        final int controlType = (int) buffer.readUnsignedInt();
        Log.trace("Received control frame #{}", controlType);
        final int payloadSize = controlSize - 4;
        byte[] payload = new byte[payloadSize];
        buffer.readBytes(payload, 0, payloadSize);
        checkpoint(DecodingState.FRAME_SIZE);
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
        return null;
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
