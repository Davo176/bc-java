package org.bouncycastle.pqc.crypto.ntruprime;

import org.bouncycastle.util.Arrays;

public class NTRULPRimePrivateKeyParameters
    extends NTRULPRimeKeyParameters
{
    private final byte[] enca;
    private final byte[] pk;
    private final byte[] rho;
    private final byte[] hash;

    public NTRULPRimePrivateKeyParameters(NTRULPRimeParameters params, byte[] enca, byte[] pk, byte[] rho, byte[] hash)
    {
        super(true, params);
        this.enca = Arrays.clone(enca);
        this.pk = Arrays.clone(pk);
        this.rho = Arrays.clone(rho);
        this.hash = Arrays.clone(hash);
    }

    public NTRULPRimePrivateKeyParameters(NTRULPRimeParameters params, byte[] sk)
    {
        super(true, params);
        int encaLength = (params.getP()+3) / 4;
        int pkLength = params.getPublicKeyBytes();
        int rhoLength = 32;

        this.enca = Arrays.copyOfRange(sk,0,encaLength);
        this.pk = Arrays.copyOfRange(sk,encaLength,encaLength+pkLength);
        this.rho = Arrays.copyOfRange(sk,encaLength+pkLength,encaLength+pkLength+rhoLength);
        this.hash = Arrays.copyOfRange(sk,encaLength+pkLength+rhoLength,sk.length);
    }


    public byte[] getEnca()
    {
        return Arrays.clone(enca);
    }

    public byte[] getPk()
    {
        return Arrays.clone(pk);
    }

    public byte[] getRho()
    {
        return Arrays.clone(rho);
    }

    public byte[] getHash()
    {
        return Arrays.clone(hash);
    }

    public byte[] getEncoded()
    {
        byte[] key = new byte[getParameters().getPrivateKeyBytes()];
        System.arraycopy(enca, 0, key, 0, enca.length);
        System.arraycopy(pk, 0, key, enca.length, pk.length);
        System.arraycopy(rho, 0, key, enca.length + pk.length, rho.length);
        System.arraycopy(hash, 0, key, enca.length + pk.length + rho.length, hash.length);
        return key;
    }
}
