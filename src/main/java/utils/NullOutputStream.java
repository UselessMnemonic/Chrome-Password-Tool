package utils;

import java.io.OutputStream;

public class NullOutputStream extends OutputStream {
    public void write(int b) {}

    public void write(byte[] b) {}

    public void write(byte[] b, int off, int len) {}
}
