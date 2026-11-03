package dev.portal.autoroothelper;

import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Arrays;
import java.util.Base64;

import javax.crypto.Cipher;

/** Minimal classic ADB client for the device's loopback-only boot action. */
final class AdbClient implements AutoCloseable {
    private static final int A_CNXN = command("CNXN");
    private static final int A_OPEN = command("OPEN");
    private static final int A_OKAY = command("OKAY");
    private static final int A_CLSE = command("CLSE");
    private static final int A_WRTE = command("WRTE");
    private static final int A_AUTH = command("AUTH");
    private static final int AUTH_TOKEN = 1;
    private static final int AUTH_SIGNATURE = 2;
    private static final int VERSION = 0x01000000;
    private static final int MAX_DATA = 4096;
    private static final int MAX_PACKET = 1024 * 1024;

    private static final byte[] SHA1_DIGEST_INFO = new byte[] {
        0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e,
        0x03, 0x02, 0x1a, 0x05, 0x00, 0x04, 0x14
    };

    private final Socket socket;
    private final DataInputStream input;
    private final DataOutputStream output;
    private final PrivateKey privateKey;

    AdbClient(File keyDirectory) throws Exception {
        privateKey = readPrivateKey(new File(keyDirectory, "adbkey"));
        socket = new Socket();
        socket.connect(new InetSocketAddress(
                InetAddress.getByName("127.0.0.1"), 5555), 5000);
        socket.setTcpNoDelay(true);
        socket.setSoTimeout(15000);
        input = new DataInputStream(socket.getInputStream());
        output = new DataOutputStream(socket.getOutputStream());
    }

    void connect() throws Exception {
        write(A_CNXN, VERSION, MAX_DATA, bytes("host::\0"));
        Message message = read();
        if (message.command == A_AUTH && message.arg0 == AUTH_TOKEN) {
            write(A_AUTH, AUTH_SIGNATURE, 0, sign(message.data));
            message = read();
            if (message.command == A_AUTH) {
                throw new IllegalStateException("Portal helper ADB key is not authorized");
            }
        }
        if (message.command != A_CNXN) {
            throw new IllegalStateException("ADB authentication failed");
        }
    }

    String shell(String command) throws Exception {
        int localId = 1;
        write(A_OPEN, localId, 0, bytes("shell:" + command + "\0"));
        Message message = read();
        if (message.command == A_CLSE) {
            write(A_CLSE, localId, message.arg0, null);
            return "";
        }
        if (message.command != A_OKAY) {
            throw new IllegalStateException("ADB shell open failed");
        }
        ByteArrayOutputStream result = new ByteArrayOutputStream();
        while (true) {
            message = read();
            if (message.command == A_WRTE) {
                if (message.data != null) result.write(message.data);
                write(A_OKAY, localId, message.arg0, null);
            } else if (message.command == A_CLSE) {
                write(A_CLSE, localId, message.arg0, null);
                return result.toString("UTF-8");
            } else {
                throw new IllegalStateException("unexpected ADB shell packet");
            }
        }
    }

    private byte[] sign(byte[] token) throws Exception {
        if (token == null || token.length != 20) {
            throw new IllegalArgumentException("unexpected ADB token");
        }
        byte[] padded = new byte[256];
        padded[0] = 0;
        padded[1] = 1;
        Arrays.fill(padded, 2, padded.length - SHA1_DIGEST_INFO.length - token.length - 1,
                (byte) 0xff);
        int separator = padded.length - SHA1_DIGEST_INFO.length - token.length - 1;
        padded[separator] = 0;
        System.arraycopy(SHA1_DIGEST_INFO, 0, padded, separator + 1,
                SHA1_DIGEST_INFO.length);
        System.arraycopy(token, 0, padded, padded.length - token.length, token.length);
        Cipher cipher = Cipher.getInstance("RSA/ECB/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, privateKey);
        return cipher.doFinal(padded);
    }

    private void write(int command, int arg0, int arg1, byte[] data) throws Exception {
        int length = data == null ? 0 : data.length;
        int checksum = 0;
        if (data != null) for (byte value : data) checksum += value & 0xff;
        ByteBuffer header = ByteBuffer.allocate(24).order(ByteOrder.LITTLE_ENDIAN);
        header.putInt(command).putInt(arg0).putInt(arg1).putInt(length)
                .putInt(checksum).putInt(command ^ 0xffffffff);
        output.write(header.array());
        if (data != null) output.write(data);
        output.flush();
    }

    private Message read() throws Exception {
        byte[] rawHeader = new byte[24];
        input.readFully(rawHeader);
        ByteBuffer header = ByteBuffer.wrap(rawHeader).order(ByteOrder.LITTLE_ENDIAN);
        int command = header.getInt();
        int arg0 = header.getInt();
        int arg1 = header.getInt();
        int length = header.getInt();
        int expectedChecksum = header.getInt();
        int magic = header.getInt();
        if (magic != (command ^ 0xffffffff) || length < 0 || length > MAX_PACKET) {
            throw new IllegalStateException("invalid ADB packet header");
        }
        byte[] data = length == 0 ? null : new byte[length];
        if (data != null) input.readFully(data);
        int checksum = 0;
        if (data != null) for (byte value : data) checksum += value & 0xff;
        if (checksum != expectedChecksum) {
            throw new IllegalStateException("invalid ADB packet checksum");
        }
        return new Message(command, arg0, arg1, data);
    }

    private static PrivateKey readPrivateKey(File file) throws Exception {
        String pem = readFile(file)
                .replace("-----BEGIN PRIVATE KEY-----", "")
                .replace("-----END PRIVATE KEY-----", "")
                .replaceAll("\\s", "");
        byte[] encoded = Base64.getDecoder().decode(pem);
        return KeyFactory.getInstance("RSA").generatePrivate(new PKCS8EncodedKeySpec(encoded));
    }

    private static String readFile(File file) throws Exception {
        FileInputStream input = new FileInputStream(file);
        try {
            ByteArrayOutputStream output = new ByteArrayOutputStream();
            byte[] buffer = new byte[4096];
            int count;
            while ((count = input.read(buffer)) != -1) output.write(buffer, 0, count);
            return output.toString("UTF-8");
        } finally {
            input.close();
        }
    }

    private static byte[] bytes(String value) {
        return value.getBytes(StandardCharsets.UTF_8);
    }

    private static int command(String value) {
        return value.charAt(0) | value.charAt(1) << 8 |
                value.charAt(2) << 16 | value.charAt(3) << 24;
    }

    @Override
    public void close() throws Exception {
        socket.close();
    }

    private static final class Message {
        final int command;
        final int arg0;
        final int arg1;
        final byte[] data;

        Message(int command, int arg0, int arg1, byte[] data) {
            this.command = command;
            this.arg0 = arg0;
            this.arg1 = arg1;
            this.data = data;
        }
    }
}
