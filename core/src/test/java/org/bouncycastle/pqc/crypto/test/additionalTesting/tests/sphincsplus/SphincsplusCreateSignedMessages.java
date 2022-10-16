package org.bouncycastle.pqc.crypto.test.additionalTesting.tests.sphincsplus;

import junit.framework.TestCase;
import java.io.*;
import java.security.SecureRandom;

import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.pqc.crypto.test.NISTSecureRandom;
import org.bouncycastle.crypto.params.ParametersWithRandom;

import org.bouncycastle.crypto.SecretWithEncapsulation;
import org.bouncycastle.pqc.crypto.sphincsplus.SPHINCSPlusSigner;
import org.bouncycastle.pqc.crypto.sphincsplus.SPHINCSPlusParameters;
import org.bouncycastle.pqc.crypto.sphincsplus.SPHINCSPlusPrivateKeyParameters;
import org.bouncycastle.util.test.FixedSecureRandom;
import org.bouncycastle.util.Arrays;

public class SphincsplusCreateSignedMessages extends TestCase
{
    public void testCreateSignedMessages() 
        throws Exception
    {
        String files[] = new String[]{
            "keypairs_ref_haraka-128f-robust.rsp",
            "keypairs_ref_haraka-128f-simple.rsp",
            "keypairs_ref_haraka-128s-robust.rsp",
            "keypairs_ref_haraka-128s-simple.rsp",
            "keypairs_ref_haraka-192f-robust.rsp",
            "keypairs_ref_haraka-192f-simple.rsp",
            "keypairs_ref_haraka-192s-robust.rsp",
            "keypairs_ref_haraka-192s-simple.rsp",
            "keypairs_ref_haraka-256f-robust.rsp",
            "keypairs_ref_haraka-256f-simple.rsp",
            "keypairs_ref_haraka-256s-robust.rsp",
            "keypairs_ref_haraka-256s-simple.rsp",
            "keypairs_ref_sha2-128f-robust.rsp",
            "keypairs_ref_sha2-128f-simple.rsp",
            "keypairs_ref_sha2-128s-robust.rsp",
            "keypairs_ref_sha2-128s-simple.rsp",
            "keypairs_ref_sha2-192f-robust.rsp",
            "keypairs_ref_sha2-192f-simple.rsp",
            "keypairs_ref_sha2-192s-robust.rsp",
            "keypairs_ref_sha2-192s-simple.rsp",
            "keypairs_ref_sha2-256f-robust.rsp",
            "keypairs_ref_sha2-256f-simple.rsp",
            "keypairs_ref_sha2-256s-robust.rsp",
            "keypairs_ref_sha2-256s-simple.rsp",
            "keypairs_ref_shake-128f-robust.rsp",
            "keypairs_ref_shake-128f-simple.rsp",
            "keypairs_ref_shake-128s-robust.rsp",
            "keypairs_ref_shake-128s-simple.rsp",
            "keypairs_ref_shake-192f-robust.rsp",
            "keypairs_ref_shake-192f-simple.rsp",
            "keypairs_ref_shake-192s-robust.rsp",
            "keypairs_ref_shake-192s-simple.rsp",
            "keypairs_ref_shake-256f-robust.rsp",
            "keypairs_ref_shake-256f-simple.rsp",
            "keypairs_ref_shake-256s-robust.rsp",
            "keypairs_ref_shake-256s-simple.rsp",
        };

        String[] newFiles = new String[]{
            "signed_java_haraka-128f-robust.rsp",
            "signed_java_haraka-128f-simple.rsp",
            "signed_java_haraka-128s-robust.rsp",
            "signed_java_haraka-128s-simple.rsp",
            "signed_java_haraka-192f-robust.rsp",
            "signed_java_haraka-192f-simple.rsp",
            "signed_java_haraka-192s-robust.rsp",
            "signed_java_haraka-192s-simple.rsp",
            "signed_java_haraka-256f-robust.rsp",
            "signed_java_haraka-256f-simple.rsp",
            "signed_java_haraka-256s-robust.rsp",
            "signed_java_haraka-256s-simple.rsp",
            "signed_java_sha2-128f-robust.rsp",
            "signed_java_sha2-128f-simple.rsp",
            "signed_java_sha2-128s-robust.rsp",
            "signed_java_sha2-128s-simple.rsp",
            "signed_java_sha2-192f-robust.rsp",
            "signed_java_sha2-192f-simple.rsp",
            "signed_java_sha2-192s-robust.rsp",
            "signed_java_sha2-192s-simple.rsp",
            "signed_java_sha2-256f-robust.rsp",
            "signed_java_sha2-256f-simple.rsp",
            "signed_java_sha2-256s-robust.rsp",
            "signed_java_sha2-256s-simple.rsp",
            "signed_java_shake-128f-robust.rsp",
            "signed_java_shake-128f-simple.rsp",
            "signed_java_shake-128s-robust.rsp",
            "signed_java_shake-128s-simple.rsp",
            "signed_java_shake-192f-robust.rsp",
            "signed_java_shake-192f-simple.rsp",
            "signed_java_shake-192s-robust.rsp",
            "signed_java_shake-192s-simple.rsp",
            "signed_java_shake-256f-robust.rsp",
            "signed_java_shake-256f-simple.rsp",
            "signed_java_shake-256s-robust.rsp",
            "signed_java_shake-256s-simple.rsp",
        };

        SPHINCSPlusParameters[] paramList = new SPHINCSPlusParameters[]{
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

        

        for (int fileIndex = 0; fileIndex < files.length; fileIndex++)
        {
            String newFileName = newFiles[fileIndex];
            try {
            File myObj = new File("src/test/java/org/bouncycastle/pqc/crypto/test/additionalTesting/resources/sphincsplus/interoperability/"+newFileName);
            if (myObj.createNewFile()) {
                    System.out.println("File created: " + myObj.getName());
            } else {
                    System.out.println("File already exists.");
            }
            } catch (IOException e) {
                System.out.println("An error occurred.");
                e.printStackTrace();
            }
            
            FileWriter newFile = new FileWriter("src/test/java/org/bouncycastle/pqc/crypto/test/additionalTesting/resources/sphincsplus/interoperability/"+newFileName);
            String name = files[fileIndex];
            System.out.println("testing: " + name);
            InputStream src = SphincsplusCreateSignedMessages.class.getResourceAsStream("/org/bouncycastle/pqc/crypto/test/additionalTesting/resources/sphincsplus/interoperability/" + name);
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


                //convert all into byte arrays
                byte[] sk = Hex.decode(secretKeyString);
                byte[] msg = Hex.decode(messageString); // message
                int m_len = Integer.parseInt(mlenString);


                System.out.println("Testing Case: "+count);
                
                byte[] entropy_input = new byte[48];
                for (int i=0;i<48;i++){
                    entropy_input[i]=(byte)i;
                }

                SecureRandom random = new FixedSecureRandom(entropy_input);
                
                SPHINCSPlusParameters parameters = paramList[fileIndex];

                //
                // Generate keys and test.
                //

                SPHINCSPlusPrivateKeyParameters privateKeyParams = new SPHINCSPlusPrivateKeyParameters(parameters,sk);

                System.out.println("test1");
                
                //
                // Signature test
                //
                SPHINCSPlusSigner signer = new SPHINCSPlusSigner();
                
                signer.init(true, new ParametersWithRandom(privateKeyParams, random));
                
                byte[] sigGenerated = signer.generateSignature(msg);
                byte[] attachedSig = Arrays.concatenate(sigGenerated, msg);

                newFile.write("count = "+count+"\n");
                newFile.write("pk = "+publicKeyString+"\n");
                newFile.write("mlen = "+mlenString+"\n");
                newFile.write("msg = "+messageString+"\n");
                newFile.write("smlen = "+Integer.toString(attachedSig.length)+"\n");
                newFile.write("sm = "+Hex.toHexString(attachedSig)+"\n");
                newFile.write("\n");
            }
            newFile.close();
        }
    }
}