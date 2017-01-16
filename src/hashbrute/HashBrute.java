/*
 * Copyright (C) 2017 The Mighty Beerhammer
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */
package hashbrute;

/**
 *
 * @author The Mighty Beerhammer
 */
public class HashBrute {

    /**
     * @param args the command line arguments
     */
    public static void main(String[] args) {
        HashBrute app = new HashBrute();
        String message = "ask for link to public copy";
        SHA256 sha = SHA256.getInstance();
        sha.SetMessage(message);
        
        System.out.println("Original message: " + message);
        System.out.println("Calculated hash:  " + sha.GetHash());
    }
    
}

class SHA256 {
    private static SHA256 instance = null;
    private String message = "";
    private String m = "";
    private int[] data;
    
    private final int[] k = {
        0x428A2F98, 0x71374491, 0xB5C0FBCF, 0xE9B5DBA5, 0x3956C25B, 0x59F111F1, 0x923F82A4, 0xAB1C5ED5,
        0xD807AA98, 0x12835B01, 0x243185BE, 0x550C7DC3, 0x72BE5D74, 0x80DEB1FE, 0x9BDC06A7, 0xC19BF174,
        0xE49B69C1, 0xEFBE4786, 0x0FC19DC6, 0x240CA1CC, 0x2DE92C6F, 0x4A7484AA, 0x5CB0A9DC, 0x76F988DA,
        0x983E5152, 0xA831C66D, 0xB00327C8, 0xBF597FC7, 0xC6E00BF3, 0xD5A79147, 0x06CA6351, 0x14292967,
        0x27B70A85, 0x2E1B2138, 0x4D2C6DFC, 0x53380D13, 0x650A7354, 0x766A0ABB, 0x81C2C92E, 0x92722C85,
        0xA2BFE8A1, 0xA81A664B, 0xC24B8B70, 0xC76C51A3, 0xD192E819, 0xD6990624, 0xF40E3585, 0x106AA070,
        0x19A4C116, 0x1E376C08, 0x2748774C, 0x34B0BCB5, 0x391C0CB3, 0x4ED8AA4A, 0x5B9CCA4F, 0x682E6FF3,
        0x748F82EE, 0x78A5636F, 0x84C87814, 0x8CC70208, 0x90BEFFFA, 0xA4506CEB, 0xBEF9A3F7, 0xC67178F2
    };
    
    private SHA256() {}
    
    public static synchronized SHA256 getInstance() {
        if(instance == null) instance = new SHA256();
        return instance;
    }
    
    public void SetMessage(String m) {
        this.message = m;
    }
    
    public String GetMessage() {
        return this.message;
    }
    
    private int Append(int n, char c) {
        n <<= 8;
        n += c;
        return n;
    }
    
    private int Append(int n, byte b) {
        n <<= 8;
        n += Byte.toUnsignedInt(b);
        return n;
    }
    
    public String GetHash() {
        data = new int[message.length() / 4 + 1 + CalcMinMod448(message.length() * 8) / 32 + 2];
        for(int i = 0; i < message.length(); i++) {
            data[i / 4] = Append(data[i / 4], message.charAt(i));
        }
        data[message.length() / 4] = Append(data[message.length() / 4], (byte)128);
        for(int i = message.length() + 1; i < message.length() + (4 -(message.length() % 4)); i++) {
            data[i / 4] = Append(data[i / 4], (byte)0);
        }
        data[data.length - 1] = message.length() * 8;
        
        int h0 = 0x6A09E667;
        int h1 = 0xBB67AE85;
        int h2 = 0x3C6EF372;
        int h3 = 0xA54FF53A;
        int h4 = 0x510E527F;
        int h5 = 0x9B05688C;
        int h6 = 0x1F83D9AB;
        int h7 = 0x5BE0CD19;
        
        for(int chunk = 0; chunk < data.length / 16; chunk++) {
            int[] w = {
                0,0,0,0,0,0,0,0,
                0,0,0,0,0,0,0,0,
                0,0,0,0,0,0,0,0,
                0,0,0,0,0,0,0,0,
                0,0,0,0,0,0,0,0,
                0,0,0,0,0,0,0,0,
                0,0,0,0,0,0,0,0,
                0,0,0,0,0,0,0,0
            };
            
            for(int i = 0; i < 16; i++) {
                w[i] = data[chunk * 16 + i];
            }
            
            for(int i = 16; i < w.length; i++) {
                int s0 = RotR(w[i - 15], 7) ^ RotR(w[i - 15], 18) ^ (w[i - 15] >>> 3);
                int s1 = RotR(w[i - 2], 17) ^ RotR(w[i - 2], 19) ^ (w[i - 2] >>> 10);
                w[i] = w[i - 16] + s0 + w[i - 7] + s1;
            }

            int a = h0;
            int b = h1;
            int c = h2;
            int d = h3;
            int e = h4;
            int f = h5;
            int g = h6;
            int h = h7;

            for(int i = 0; i < 64; i++) {
                int S0 = RotR(a, 2) ^ RotR(a, 13) ^ RotR(a, 22);
                int maj = (a & b) ^ (a & c) ^ (b & c);
                int S1 = RotR(e, 6) ^ RotR(e, 11) ^ RotR(e, 25);
                int ch = (e & f) ^ (Not(e) & g);
                int temp1 = h + S1 + ch + k[i] + w[i];
                int temp2 = S0 + maj;

                h = g;
                g = f;
                f = e;
                e = d + temp1;
                d = c;
                c = b;
                b = a;
                a = temp1 + temp2;
            }
            
            h0 += a;
            h1 += b;
            h2 += c;
            h3 += d;
            h4 += e;
            h5 += f;
            h6 += g;
            h7 += h;
        }
        
        m = FillWithZeros(Integer.toHexString(h0), 8)
                + FillWithZeros(Integer.toHexString(h1), 8)
                + FillWithZeros(Integer.toHexString(h2), 8)
                + FillWithZeros(Integer.toHexString(h3), 8)
                + FillWithZeros(Integer.toHexString(h4), 8)
                + FillWithZeros(Integer.toHexString(h5), 8)
                + FillWithZeros(Integer.toHexString(h6), 8)
                + FillWithZeros(Integer.toHexString(h7), 8);
        
        return m;
    }
    
    private int CalcMinMod448(int l) {
        int k = 0;
        while((k + l) % 512 != 448) k++;
        return k;
    }
        
    private String FillWithZeros(String s, int n) {
        while(s.length() < n) s = "0" + s;
        return s.toUpperCase();
    }
    
    private int RotR(int a, int n) {
        a = (a >>> n) + (a << (32 - n));
        return a;
    }
    
    private int Not(int n) {
        String buff = FillWithZeros(Integer.toBinaryString(n), 32);
        buff = buff.replace("0", "2").replace("1", "0").replace("2", "1");
        return Integer.parseUnsignedInt(buff, 2);
    }
}
