package org.bouncycastle.pqc.crypto.test.additionalTesting.tests.picnic;

import java.io.BufferedReader;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.security.SecureRandom;
import java.util.HashMap;

import junit.framework.TestCase;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.pqc.crypto.picnic.PicnicKeyGenerationParameters;
import org.bouncycastle.pqc.crypto.picnic.PicnicKeyPairGenerator;
import org.bouncycastle.pqc.crypto.picnic.PicnicParameters;
import org.bouncycastle.pqc.crypto.picnic.PicnicPrivateKeyParameters;
import org.bouncycastle.pqc.crypto.picnic.PicnicPublicKeyParameters;
import org.bouncycastle.pqc.crypto.picnic.PicnicSigner;
import org.bouncycastle.pqc.crypto.util.PrivateKeyFactory;
import org.bouncycastle.pqc.crypto.util.PrivateKeyInfoFactory;
import org.bouncycastle.pqc.crypto.util.PublicKeyFactory;
import org.bouncycastle.pqc.crypto.util.SubjectPublicKeyInfoFactory;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Pack;
import org.bouncycastle.util.Strings;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.pqc.crypto.test.NISTSecureRandom;

public class PicnicTest
    extends TestCase

{
    public void testVectors()
        throws Exception
    {
        String[] files;
        PicnicParameters[] params;

        files = new String[]{
                "addRand_l1fs.rsp",
                "addRand_l1ur.rsp",
                "addRand_l3fs.rsp",
                "addRand_l3ur.rsp",
                "addRand_l5fs.rsp",
                "addRand_l5ur.rsp",
                "addRand_3l1.rsp",
                "addRand_3l3.rsp",
                "addRand_3l5.rsp",
                "addRand_l1full.rsp",
                "addRand_l3full.rsp",
                "addRand_l5full.rsp",

        };
        params = new PicnicParameters[]{
                PicnicParameters.picnicl1fs,
                PicnicParameters.picnicl1ur,
                PicnicParameters.picnicl3fs,
                PicnicParameters.picnicl3ur,
                PicnicParameters.picnicl5fs,
                PicnicParameters.picnicl5ur,
                PicnicParameters.picnic3l1,
                PicnicParameters.picnic3l3,
                PicnicParameters.picnic3l5,
                PicnicParameters.picnicl1full,
                PicnicParameters.picnicl3full,
                PicnicParameters.picnicl5full
        };
        
        for (int fileIndex = 0; fileIndex != files.length; fileIndex++)
        {
            String name = files[fileIndex];
            System.out.println("testing: " + name);
            InputStream src = PicnicTest.class.getResourceAsStream("/org/bouncycastle/pqc/crypto/test/additionalTesting/resources/picnic/" + name);
            BufferedReader br = new BufferedReader(new InputStreamReader(src));

            String line = null;
            while ((line = br.readLine()) != null){
                //Find next test
                int countIndex = line.indexOf("count = ");
                while (countIndex < 0){
                    line = br.readLine();
                    countIndex = line.indexOf("count = ");
                }
                String count = line.substring(countIndex + "count = ".length()).trim();
                line = br.readLine();
                
                //Get Sed
                int seedIndex = line.indexOf("seed = ");
                String seedString = line.substring(seedIndex + "seed = ".length()).trim();
                line = br.readLine();
                //Get Message Length
                int mlenIndex = line.indexOf("mlen = ");
                String mlenString = line.substring(mlenIndex + "mlen = ".length()).trim();
                line = br.readLine();
                //Get Message
                int messageIndex = line.indexOf("msg = ");
                String messageString = line.substring(messageIndex + "msg = ".length()).trim();
                line = br.readLine();
                //Get Secret Key
                int publicKeyIndex = line.indexOf("pk = ");
                String publicKeyString = line.substring(publicKeyIndex + "pk = ".length()).trim();
                line = br.readLine();
                //Get Secret Key
                int secretKeyIndex = line.indexOf("sk = ");
                String secretKeyString = line.substring(secretKeyIndex + "sk = ".length()).trim();
                line = br.readLine();
                //Get signed message length
                int smlenIndex = line.indexOf("smlen = ");
                String smlenString = line.substring(smlenIndex + "smlen = ".length()).trim();
                line = br.readLine();
                //Get Shared Secret (session key)
                int smIndex = line.indexOf("sm = ");
                String smString = line.substring(smIndex + "sm = ".length()).trim();
                line = br.readLine();

                //convert all into byte arrays
                byte[] seed = Hex.decode(seedString); // seed for Falcon secure random
                byte[] expectedPk = Hex.decode(publicKeyString);
                byte[] expectedSk = Hex.decode(secretKeyString);
                byte[] expectedSm = Hex.decode(smString);     // signed message
                int expectedSm_len = Integer.parseInt(smlenString);
                byte[] msg = Hex.decode(messageString); // message
                int m_len = Integer.parseInt(mlenString);

                System.out.println("Testing Case: "+count);

                //Get Parameters
                NISTSecureRandom random = new NISTSecureRandom(seed, null);
                PicnicParameters parameters = params[fileIndex];


                PicnicKeyPairGenerator kpGen = new PicnicKeyPairGenerator();
                PicnicKeyGenerationParameters genParams = new PicnicKeyGenerationParameters(random, parameters);
                //
                // Generate keys and test.
                //
                kpGen.init(genParams);
                AsymmetricCipherKeyPair kp = kpGen.generateKeyPair();


                PicnicPublicKeyParameters pubParams = (PicnicPublicKeyParameters) PublicKeyFactory.createKey(SubjectPublicKeyInfoFactory.createSubjectPublicKeyInfo(kp.getPublic()));
                PicnicPrivateKeyParameters privParams = (PicnicPrivateKeyParameters) PrivateKeyFactory.createKey(PrivateKeyInfoFactory.createPrivateKeyInfo(kp.getPrivate()));

                assertTrue(name + " " + count + ": public key", Arrays.areEqual(expectedPk, pubParams.getEncoded()));
                assertTrue(name + " " + count + ": secret key", Arrays.areEqual(expectedSk, privParams.getEncoded()));

                PicnicSigner signer = new PicnicSigner();

                signer.init(true, privParams);

                byte[] sigGenerated = signer.generateSignature(msg);
                byte[] attachedSig = Arrays.concatenate(Pack.intToLittleEndian(sigGenerated.length), msg, sigGenerated);

                assertEquals(name + " " + count + ": signature length", expectedSm_len, attachedSig.length);

                signer.init(false, pubParams);

                assertTrue(name + " " + count + ": signature verify", signer.verifySignature(msg, sigGenerated));
                assertTrue(name + " " + count + ": signature gen match", Arrays.areEqual(expectedSm, attachedSig));
            }
        }
    }
}
