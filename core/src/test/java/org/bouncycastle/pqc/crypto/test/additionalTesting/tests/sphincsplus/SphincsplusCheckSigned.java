package org.bouncycastle.pqc.crypto.test.additionalTesting.tests.sphincsplus;

import java.io.BufferedReader;
import java.io.Console;
import java.io.InputStream;
import java.io.InputStreamReader;

import junit.framework.TestCase;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.pqc.crypto.sphincsplus.SPHINCSPlusParameters;
import org.bouncycastle.pqc.crypto.sphincsplus.SPHINCSPlusPublicKeyParameters;
import org.bouncycastle.pqc.crypto.sphincsplus.SPHINCSPlusSigner;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.test.FixedSecureRandom;

public class SphincsplusCheckSigned extends TestCase
{
    public void testVectors()
        throws Exception
    {
        String files[] = new String[]{
            "signed_java_ref_haraka-128f-robust.rsp",
            "signed_java_ref_haraka-128f-simple.rsp",
            "signed_java_ref_haraka-128s-robust.rsp",
            "signed_java_ref_haraka-128s-simple.rsp",
            "signed_java_ref_haraka-192f-robust.rsp",
            "signed_java_ref_haraka-192f-simple.rsp",
            "signed_java_ref_haraka-192s-robust.rsp",
            "signed_java_ref_haraka-192s-simple.rsp",
            "signed_java_ref_haraka-256f-robust.rsp",
            "signed_java_ref_haraka-256f-simple.rsp",
            "signed_java_ref_haraka-256s-robust.rsp",
            "signed_java_ref_haraka-256s-simple.rsp",
            "signed_java_ref_sha2-128f-robust.rsp",
            "signed_java_ref_sha2-128f-simple.rsp",
            "signed_java_ref_sha2-128s-robust.rsp",
            "signed_java_ref_sha2-128s-simple.rsp",
            "signed_java_ref_sha2-192f-robust.rsp",
            "signed_java_ref_sha2-192f-simple.rsp",
            "signed_java_ref_sha2-192s-robust.rsp",
            "signed_java_ref_sha2-192s-simple.rsp",
            "signed_java_ref_sha2-256f-robust.rsp",
            "signed_java_ref_sha2-256f-simple.rsp",
            "signed_java_ref_sha2-256s-robust.rsp",
            "signed_java_ref_sha2-256s-simple.rsp",
            "signed_java_ref_shake-128f-robust.rsp",
            "signed_java_ref_shake-128f-simple.rsp",
            "signed_java_ref_shake-128s-robust.rsp",
            "signed_java_ref_shake-128s-simple.rsp",
            "signed_java_ref_shake-192f-robust.rsp",
            "signed_java_ref_shake-192f-simple.rsp",
            "signed_java_ref_shake-192s-robust.rsp",
            "signed_java_ref_shake-192s-simple.rsp",
            "signed_java_ref_shake-256f-robust.rsp",
            "signed_java_ref_shake-256f-simple.rsp",
            "signed_java_ref_shake-256s-robust.rsp",
            "signed_java_ref_shake-256s-simple.rsp",
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
            InputStream src = SphincsplusTest.class.getResourceAsStream("/org/bouncycastle/pqc/crypto/test/additionalTesting/resources/sphincsplus/interoperability/" + name);
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
                System.out.println(smIndex);
                String smString = line.substring(smIndex + "sm = ".length()).trim();
                line = br.readLine();
                

                //convert all into byte arrays
                byte[] pk = Hex.decode(publicKeyString);
                byte[] sm = Hex.decode(smString);     // signed message
                byte[] msg = Hex.decode(messageString); // message
                int mlen = Integer.parseInt(mlenString);
                int smlen = Integer.parseInt(smlenString);
                System.out.println("Testing Case: "+count);
                SPHINCSPlusParameters parameters = params[i];

                //
                // Signature test
                //

                SPHINCSPlusPublicKeyParameters publicKeyParams = new SPHINCSPlusPublicKeyParameters(parameters,pk);

                SPHINCSPlusSigner verifier = new SPHINCSPlusSigner();

                verifier.init(false, publicKeyParams);

                byte[] detachedSign = Arrays.copyOfRange(sm, 0, smlen-mlen);
                boolean valid = verifier.verifySignature(msg,detachedSign);

                assertTrue(name + " " + count + ": signature gen match",valid);

                System.out.println("hit");
                if(count.equals("99")){
                    System.out.println("hit1");
                    break;
                }
            }
        }
    }
}