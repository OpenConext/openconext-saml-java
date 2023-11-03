package saml.parser;


import lombok.SneakyThrows;
import org.apache.commons.codec.binary.Base64;

import java.io.ByteArrayOutputStream;
import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.util.zip.Deflater;
import java.util.zip.DeflaterOutputStream;
import java.util.zip.Inflater;
import java.util.zip.InflaterOutputStream;

import static java.nio.charset.StandardCharsets.ISO_8859_1;
import static java.nio.charset.StandardCharsets.UTF_8;
import static java.util.zip.Deflater.DEFLATED;

public class EncodingUtils {

    private static final Base64 UN_CHUNKED_ENCODER = new Base64(0, new byte[]{'\n'});

    private EncodingUtils() {
    }

    @SneakyThrows
    private static byte[] deflate(String s) {
        ByteArrayOutputStream b = new ByteArrayOutputStream();
        DeflaterOutputStream deflater = new DeflaterOutputStream(b, new Deflater(DEFLATED, true));
        deflater.write(s.getBytes(UTF_8));
        deflater.finish();
        return b.toByteArray();
    }

    @SneakyThrows
    private static String inflate(byte[] b) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        InflaterOutputStream iout = new InflaterOutputStream(out, new Inflater(true));
        iout.write(b);
        iout.finish();
        return out.toString(UTF_8);
    }


    public static String samlEncode(String s, boolean deflate) {
        byte[] b = deflate ? EncodingUtils.deflate(s) : s.getBytes(UTF_8);
        return UN_CHUNKED_ENCODER.encodeToString(b);
    }

    public static String toISO8859_1(String text) {
        ByteBuffer inputBuffer = ByteBuffer.wrap(text.getBytes(UTF_8));
        CharBuffer data = UTF_8.decode(inputBuffer);
        ByteBuffer outputBuffer = ISO_8859_1.encode(data);
        byte[] outputData = outputBuffer.array();
        return new String(outputData, ISO_8859_1);

    }


    public static String samlDecode(String s, boolean inflate) {
        byte[] b = UN_CHUNKED_ENCODER.decode(s);
        return inflate ? EncodingUtils.inflate(b) : new String(b, UTF_8);
    }
}
