package org.bouncycastle.pqc.crypto.ntruprime;

import org.bouncycastle.util.Arrays;

public class SNTRUPrimePrivateKeyParameters
    extends SNTRUPrimeKeyParameters
{
    private final byte[] f;
    private final byte[] ginv;
    private final byte[] pk;
    private final byte[] rho;
    private final byte[] hash;

    public SNTRUPrimePrivateKeyParameters(SNTRUPrimeParameters params, byte[] f, byte[] ginv,
                                          byte[] pk, byte[] rho, byte[] hash)
    {
        super(true, params);
        this.f = Arrays.clone(f);
        this.ginv = Arrays.clone(ginv);
        this.pk = Arrays.clone(pk);
        this.rho = Arrays.clone(rho);
        this.hash = Arrays.clone(hash);
    }

    public SNTRUPrimePrivateKeyParameters(SNTRUPrimeParameters params, byte[] sk)
    {
        super(true, params);
        int fLength = (params.getP()+3) /4;
        int ginvLength = (params.getP()+3) /4;
        int pkLength = params.getPublicKeyBytes();
        int rhoLength = (params.getP()+3) /4;

        this.f = Arrays.copyOfRange(sk,0,fLength);
        this.ginv = Arrays.copyOfRange(sk,fLength,fLength+ginvLength);
        this.pk = Arrays.copyOfRange(sk,fLength+ginvLength,fLength+ginvLength+pkLength);
        this.rho = Arrays.copyOfRange(sk,fLength+ginvLength+pkLength,fLength+ginvLength+pkLength+rhoLength);
        this.hash = Arrays.copyOfRange(sk,fLength+ginvLength+pkLength+rhoLength,sk.length);
    }


    public byte[] getF()
    {
        return Arrays.clone(f);
    }

    public byte[] getGinv()
    {
        return Arrays.clone(ginv);
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
        System.arraycopy(f, 0, key, 0, f.length);
        System.arraycopy(ginv, 0, key, f.length, ginv.length);
        System.arraycopy(pk, 0, key, f.length + ginv.length, pk.length);
        System.arraycopy(rho, 0, key, f.length + ginv.length + pk.length, rho.length);
        System.arraycopy(hash, 0, key, f.length + ginv.length + pk.length + rho.length, hash.length);
        return key;
    }
}
