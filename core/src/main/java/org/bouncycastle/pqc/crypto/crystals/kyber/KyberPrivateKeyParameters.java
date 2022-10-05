package org.bouncycastle.pqc.crypto.crystals.kyber;

import org.bouncycastle.util.Arrays;

public class KyberPrivateKeyParameters
    extends KyberKeyParameters
{
    final byte[] s;
    final byte[] hpk;
    final byte[] nonce;
    final byte[] t;
    final byte[] rho;

    public KyberPrivateKeyParameters(KyberParameters params, byte[] s, byte[] hpk, byte[] nonce, byte[] t, byte[] rho)
    {
        super(true, params);
        this.s = Arrays.clone(s);
        this.hpk = Arrays.clone(hpk);
        this.nonce = Arrays.clone(nonce);
        this.t = Arrays.clone(t);
        this.rho = Arrays.clone(rho);
    }

    public KyberPrivateKeyParameters(KyberParameters params, byte[] sk)
    {
        super(true, params);

        KyberEngine engine= params.getEngine();
        int sLength = engine.getKyberIndCpaSecretKeyBytes();
        int hpkLength = 32;
        int nonceLength = KyberEngine.KyberSymBytes;
        int tLength = engine.getKyberIndCpaSecretKeyBytes()-32;
        int rhoLength = 32; 

        this.s = Arrays.copyOfRange(sk,0,sLength);
        this.t = Arrays.copyOfRange(sk,sLength,sLength+tLength);
        this.rho = Arrays.copyOfRange(sk,sLength+tLength,sLength+tLength+rhoLength);
        this.hpk = Arrays.copyOfRange(sk,sLength+tLength+nonceLength,sLength+tLength+nonceLength+rhoLength);
        this.nonce = Arrays.copyOfRange(sk,sLength+tLength+rhoLength+hpkLength,sk.length);
    }

    public byte[] getT()
    {
        return Arrays.clone(t);
    }

    public byte[] getRho()
    {
        return Arrays.clone(rho);
    }

    public byte[] getPrivateKey()
    {
        return Arrays.concatenate(s, getPublicKey(), hpk, nonce);
    }

    public byte[] getEncoded()
    {
        return getPrivateKey();
    }

    public byte[] getPublicKey()
    {
        return Arrays.concatenate(t, rho);
    }

    public byte[] getS()
    {
        return Arrays.clone(s);
    }

    public byte[] getHPK()
    {
        return Arrays.clone(hpk);
    }

    public byte[] getNonce()
    {
        return Arrays.clone(nonce);
    }
}
