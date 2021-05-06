package crypto;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.security.InvalidKeyException;

public class PBKDF2 {

    private int BlockSize;
    private int BlockIndex = 1;

    private byte[] BufferBytes;
    private int BufferStartIndex = 0;
    private int BufferEndIndex = 0;

    public Mac Algorithm;
    public byte[] Salt;
    public int IterationCount;

    public PBKDF2(Mac algorithm, byte[] password, byte[] salt, int iterations) throws InvalidKeyException {
        if (algorithm == null) { throw new IllegalArgumentException("Algorithm cannot be null."); }
        if (salt == null) { throw new IllegalArgumentException("Salt cannot be null."); }
        if (password == null) { throw new IllegalArgumentException("Password cannot be null."); }
        this.Algorithm = algorithm;
        algorithm.init(new SecretKeySpec(password, algorithm.getAlgorithm()));
        this.Salt = salt;
        this.IterationCount = iterations;
        this.BlockSize = algorithm.getMacLength();
        this.BufferBytes = new byte[this.BlockSize];
    }

    public byte[] GetBytes(int count) {
        return GetBytes(count, "sha512");
    }

    public byte[] GetBytes(int count, String algorithm) {
        byte[] result = new byte[count];
        int resultOffset = 0;
        int bufferCount = this.BufferEndIndex - this.BufferStartIndex;

        if (bufferCount > 0) { //if there is some data in buffer
            if (count < bufferCount) { //if there is enough data in buffer
                System.arraycopy(this.BufferBytes, this.BufferStartIndex, result, 0, count);
                this.BufferStartIndex += count;
                return result;
            }
            System.arraycopy(this.BufferBytes, this.BufferStartIndex, result, 0, bufferCount);
            this.BufferStartIndex = this.BufferEndIndex = 0;
            resultOffset += bufferCount;
        }

        while (resultOffset < count) {
            int needCount = count - resultOffset;
            if (algorithm.equalsIgnoreCase("sha256"))
                this.BufferBytes = this.Func(false);
            else
                this.BufferBytes = this.Func();
            if (needCount > this.BlockSize) { //we one (or more) additional passes
                System.arraycopy(this.BufferBytes, 0, result, resultOffset, this.BlockSize);
                resultOffset += this.BlockSize;
            } else {
                System.arraycopy(this.BufferBytes, 0, result, resultOffset, needCount);
                this.BufferStartIndex = needCount;
                this.BufferEndIndex = this.BlockSize;
                return result;
            }
        }
        return result;
    }

    private byte[] Func() {
        return Func(true);
    }

    private byte[] Func(boolean mscrypto) {
        byte[] hash1Input = new byte[this.Salt.length + 4];
        System.arraycopy(this.Salt, 0, hash1Input, 0, this.Salt.length);
        System.arraycopy(GetBytesFromInt(this.BlockIndex), 0, hash1Input, this.Salt.length, 4);
        byte[] hash1 = this.Algorithm.doFinal(hash1Input);

        byte[] finalHash = hash1;
        for (int i = 2; i <= this.IterationCount; i++) {
            hash1 = this.Algorithm.doFinal(hash1);
            for (int j = 0; j < this.BlockSize; j++) {
                finalHash[j] = (byte)(finalHash[j] ^ hash1[j]);
            }
            if (mscrypto)
                System.arraycopy(finalHash, 0, hash1, 0, hash1.length);
            // https://github.com/gentilkiwi/mimikatz/blob/110a831ebe7b529c5dd3010f9e7fced0d3e3a46c/modules/kull_m_crypto.c#L207
        }

        if (this.BlockIndex == Integer.MAX_VALUE) {
            throw new UnsupportedOperationException("Derived key too long.");
        }
        this.BlockIndex += 1;

        return finalHash;
    }

    private static byte[] GetBytesFromInt(int i) {
        ByteBuffer buffer = ByteBuffer.allocate(4);
        buffer.putInt(i);
        byte[] bytes = buffer.array();
        if (buffer.order() == ByteOrder.LITTLE_ENDIAN) {
            return new byte[] { bytes[3], bytes[2], bytes[1], bytes[0] };
        } else {
            return bytes;
        }
    }

}
