package org.bouncycastle.pqc.crypto.test.additionalTesting.tests.sphincsplus;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;

import junit.framework.TestCase;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.pqc.crypto.sphincsplus.SPHINCSPlusKeyGenerationParameters;
import org.bouncycastle.pqc.crypto.sphincsplus.SPHINCSPlusKeyPairGenerator;
import org.bouncycastle.pqc.crypto.sphincsplus.SPHINCSPlusParameters;
import org.bouncycastle.pqc.crypto.sphincsplus.SPHINCSPlusPrivateKeyParameters;
import org.bouncycastle.pqc.crypto.sphincsplus.SPHINCSPlusPublicKeyParameters;
import org.bouncycastle.pqc.crypto.sphincsplus.SPHINCSPlusSigner;
import org.bouncycastle.pqc.crypto.util.PrivateKeyFactory;
import org.bouncycastle.pqc.crypto.util.PrivateKeyInfoFactory;
import org.bouncycastle.pqc.crypto.util.PublicKeyFactory;
import org.bouncycastle.pqc.crypto.util.SubjectPublicKeyInfoFactory;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.test.FixedSecureRandom;


public class SphincsplusTest
    extends TestCase
{
    public void testVectors()
        throws Exception
    {
        String files[] = new String[]{
            "subset_haraka-128f-robust.rsp",
            "subset_haraka-128f-simple.rsp",
            "subset_haraka-128s-robust.rsp",
            "subset_haraka-128s-simple.rsp",
            "subset_haraka-192f-robust.rsp",
            "subset_haraka-192f-simple.rsp",
            "subset_haraka-192s-robust.rsp",
            "subset_haraka-192s-simple.rsp",
            "subset_haraka-256f-robust.rsp",
            "subset_haraka-256f-simple.rsp",
            "subset_haraka-256s-robust.rsp",
            "subset_haraka-256s-simple.rsp",
            "subset_sha2-128f-robust.rsp",
            "subset_sha2-128f-simple.rsp",
            "subset_sha2-128s-robust.rsp",
            "subset_sha2-128s-simple.rsp",
            "subset_sha2-192f-robust.rsp",
            "subset_sha2-192f-simple.rsp",
            "subset_sha2-192s-robust.rsp",
            "subset_sha2-192s-simple.rsp",
            "subset_sha2-256f-robust.rsp",
            "subset_sha2-256f-simple.rsp",
            "subset_sha2-256s-robust.rsp",
            "subset_sha2-256s-simple.rsp",
            "subset_shake-128f-robust.rsp",
            "subset_shake-128f-simple.rsp",
            "subset_shake-128s-robust.rsp",
            "subset_shake-128s-simple.rsp",
            "subset_shake-192f-robust.rsp",
            "subset_shake-192f-simple.rsp",
            "subset_shake-192s-robust.rsp",
            "subset_shake-192s-simple.rsp",
            "subset_shake-256f-robust.rsp",
            "subset_shake-256f-simple.rsp",
            "subset_shake-256s-robust.rsp",
            "subset_shake-256s-simple.rsp",
        };

        SPHINCSPlusParameters[] params = new SPHINCSPlusParameters[]{
            SPHINCSPlusParameters.haraka_128f,
            SPHINCSPlusParameters.haraka_128f_simple,
            SPHINCSPlusParameters.haraka_128s,
            SPHINCSPlusParameters.haraka_128s_simple,
            SPHINCSPlusParameters.haraka_192f,
            SPHINCSPlusParameters.haraka_192f_simple,
            SPHINCSPlusParameters.haraka_192s,
            SPHINCSPlusParameters.haraka_192s_simple,
            SPHINCSPlusParameters.haraka_256f,
            SPHINCSPlusParameters.haraka_256f_simple,
            SPHINCSPlusParameters.haraka_256s,
            SPHINCSPlusParameters.haraka_256s_simple,
            SPHINCSPlusParameters.sha2_128f,
            SPHINCSPlusParameters.sha2_128f_simple,
            SPHINCSPlusParameters.sha2_128s,
            SPHINCSPlusParameters.sha2_128s_simple,
            SPHINCSPlusParameters.sha2_192f,
            SPHINCSPlusParameters.sha2_192f_simple,
            SPHINCSPlusParameters.sha2_192s,
            SPHINCSPlusParameters.sha2_192s_simple,
            SPHINCSPlusParameters.sha2_256f,
            SPHINCSPlusParameters.sha2_256f_simple,
            SPHINCSPlusParameters.sha2_256s,
            SPHINCSPlusParameters.sha2_256s_simple,
            SPHINCSPlusParameters.shake_128f,
            SPHINCSPlusParameters.shake_128f_simple,
            SPHINCSPlusParameters.shake_128s,
            SPHINCSPlusParameters.shake_128s_simple,
            SPHINCSPlusParameters.shake_192f,
            SPHINCSPlusParameters.shake_192f_simple,
            SPHINCSPlusParameters.shake_192s,
            SPHINCSPlusParameters.shake_192s_simple,
            SPHINCSPlusParameters.shake_256f,
            SPHINCSPlusParameters.shake_256f_simple,
            SPHINCSPlusParameters.shake_256s,
            SPHINCSPlusParameters.shake_256s_simple,
        };

        for (int i = 0; i != files.length; i++)
        {
            String name = files[i];
            InputStream src = SphincsplusTest.class.getResourceAsStream("/org/bouncycastle/pqc/crypto/test/sphincs_plus/" + name);
            BufferedReader br = new BufferedReader(new InputStreamReader(src));
            System.out.println(name);
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
                //Get Additional Optrand
                int optrandIndex = line.indexOf("optrand = ");
                String optrandString = line.substring(optrandIndex + "optrand = ".length()).trim();
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
                byte[] optrand = Hex.decode(optrandString); // message

                System.out.println("Testing Case: "+count);

                SPHINCSPlusKeyPairGenerator kpGen = new SPHINCSPlusKeyPairGenerator();
                SecureRandom random = new FixedSecureRandom(expectedSk);

                SPHINCSPlusParameters parameters;

                parameters = params[i];

                //
                // Generate keys and test.
                //
                kpGen.init(new SPHINCSPlusKeyGenerationParameters(random, parameters));
                AsymmetricCipherKeyPair kp = kpGen.generateKeyPair();

                SPHINCSPlusPublicKeyParameters pubParams = (SPHINCSPlusPublicKeyParameters)kp.getPublic();
                SPHINCSPlusPrivateKeyParameters privParams = (SPHINCSPlusPrivateKeyParameters)kp.getPrivate();

                System.out.println("test1");
                assertTrue(name + " " + count + ": public key", Arrays.areEqual(Arrays.concatenate(pubParams.getParameters().getEncoded(), expectedPk), pubParams.getEncoded()));
                assertTrue(name + " " + count + ": secret key", Arrays.areEqual(Arrays.concatenate(privParams.getParameters().getEncoded(), expectedSk), privParams.getEncoded()));

                //
                // Signature test
                //

                SPHINCSPlusSigner signer = new SPHINCSPlusSigner();

                signer.init(true, new ParametersWithRandom(privParams, new FixedSecureRandom(optrand)));

                byte[] sigGenerated = signer.generateSignature(msg);
                byte[] attachedSig = Arrays.concatenate(sigGenerated, msg);

                signer.init(false, pubParams);

                assertTrue(name + " " + count + ": signature verify", signer.verifySignature(msg, Arrays.copyOfRange(expectedSm, 0, sigGenerated.length)));

                assertTrue(name + " " + count + ": signature gen match", Arrays.areEqual(expectedSm, attachedSig));

            }
            src.close();
        }
    }
}