package org.bouncycastle.pqc.crypto.falcon;

import org.bouncycastle.util.Arrays;

public class FalconPrivateKeyParameters
    extends FalconKeyParameters
{
    private final byte[] pk;
    private final byte[] f;
    private final byte[] g;
    private final byte[] F;

    public FalconPrivateKeyParameters(FalconParameters parameters, byte[] f, byte[] g, byte[] F, byte[] pk_encoded)
    {
        super(true, parameters);
        this.f = Arrays.clone(f);
        this.g = Arrays.clone(g);
        this.F = Arrays.clone(F);
        this.pk = Arrays.clone(pk_encoded);
    }

    public FalconPrivateKeyParameters(FalconParameters parameters, byte[] pk_encoded)
    {
        super(true, parameters);
        int flen, glen, Flen;
        if (parameters.getName().equals("falcon-512")){
            flen=384;
            glen=384;
            Flen=512;
        }else if (parameters.getName().equals("falcon-1024")){
            flen=640;
            glen=640;
            Flen=1024;
        }else {
            flen=640;
            glen=640;
            Flen=1024;
        }

        this.f = Arrays.copyOfRange(pk_encoded,0,flen);
        this.g = Arrays.copyOfRange(pk_encoded,flen,flen+glen);
        this.F = Arrays.copyOfRange(pk_encoded,flen+glen,flen+glen+Flen);
        this.pk = Arrays.clone(pk_encoded);
    }

    public byte[] getEncoded()
    {
        return Arrays.concatenate(f, g, F);
    }

    public byte[] getPublicKey()
    {
        return Arrays.clone(pk);
    }

    public byte[] getSpolyf()
    {
        return Arrays.clone(f);
    }

    public byte[] getG()
    {
        return Arrays.clone(g);
    }

    public byte[] getSpolyF()
    {
        return Arrays.clone(F);
    }
}
