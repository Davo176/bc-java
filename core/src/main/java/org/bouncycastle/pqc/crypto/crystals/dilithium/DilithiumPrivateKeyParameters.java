package org.bouncycastle.pqc.crypto.crystals.dilithium;

import java.security.SecureRandom;
import org.bouncycastle.util.Arrays;

public class DilithiumPrivateKeyParameters
    extends DilithiumKeyParameters
{
    final byte[] rho;
    final byte[] k;
    final byte[] tr;
    final byte[] s1;
    final byte[] s2;
    final byte[] t0;

    private final byte[] t1;

    public byte[] getPrivateKey()
    {
        return getEncoded();
    }

    public DilithiumPrivateKeyParameters(DilithiumParameters params, byte[] rho, byte[] K, byte[] tr, byte[] s1, byte[] s2, byte[] t0, byte[] t1)
    {
        super(true, params);
        this.rho = Arrays.clone(rho);
        this.k = Arrays.clone(K);
        this.tr = Arrays.clone(tr);
        this.s1 = Arrays.clone(s1);
        this.s2 = Arrays.clone(s2);
        this.t0 = Arrays.clone(t0);
        this.t1 = Arrays.clone(t1);
    }

    public DilithiumPrivateKeyParameters(DilithiumParameters params, byte[] sk, SecureRandom random)
    {
        super(true, params);
        DilithiumEngine engine = params.getEngine(random);
        int rhoLength = DilithiumEngine.SeedBytes;
        int kLength = DilithiumEngine.SeedBytes;
        int trLength = DilithiumEngine.SeedBytes;
        int s1Length = engine.getDilithiumL() * engine.getDilithiumPolyEtaPackedBytes();
        int s2Length = engine.getDilithiumK() * engine.getDilithiumPolyEtaPackedBytes();
        int t0Length = engine.getDilithiumK() * DilithiumEngine.DilithiumPolyT0PackedBytes;
        
        this.rho = Arrays.copyOfRange(sk,0,rhoLength);
        this.k = Arrays.copyOfRange(sk,rhoLength,rhoLength+kLength);
        this.tr = Arrays.copyOfRange(sk,rhoLength+kLength,rhoLength+kLength+trLength);
        this.s1 = Arrays.copyOfRange(sk,rhoLength+kLength+trLength,rhoLength+kLength+trLength+s1Length);
        this.s2 = Arrays.copyOfRange(sk,rhoLength+kLength+trLength+s1Length,rhoLength+kLength+trLength+s1Length+s2Length);
        this.t0 = Arrays.copyOfRange(sk,rhoLength+kLength+trLength+s1Length+s2Length,rhoLength+kLength+trLength+s1Length+s2Length+t0Length);
        this.t1 = Arrays.copyOfRange(sk,rhoLength+kLength+trLength+s1Length+s2Length+t0Length,sk.length);
    }

    public byte[] getRho()
    {
        return Arrays.clone(rho);
    }

    public byte[] getK()
    {
        return Arrays.clone(k);
    }

    public byte[] getTr()
    {
        return Arrays.clone(tr);
    }

    public byte[] getS1()
    {
        return Arrays.clone(s1);
    }

    public byte[] getS2()
    {
        return Arrays.clone(s2);
    }

    public byte[] getT0()
    {
        return Arrays.clone(t0);
    }

    public byte[] getT1()
    {
        return t1;
    }

    public byte[] getEncoded()
    {
        return Arrays.concatenate(new byte[][] { rho, k, tr, s1, s2, t0 });
    }
}
