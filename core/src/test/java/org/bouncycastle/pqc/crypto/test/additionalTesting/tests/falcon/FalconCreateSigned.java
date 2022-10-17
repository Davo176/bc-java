package org.bouncycastle.pqc.crypto.test.additionalTesting.tests.falcon;

import junit.framework.TestCase;
import java.io.*;

//Dependencies Written by Bouncy Castle
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.pqc.crypto.test.NISTSecureRandom;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.crypto.params.ParametersWithRandom;


import org.bouncycastle.crypto.SecretWithEncapsulation;
//Asset Under Test
import org.bouncycastle.pqc.crypto.falcon.FalconParameters;
import org.bouncycastle.pqc.crypto.falcon.FalconPublicKeyParameters;
import org.bouncycastle.pqc.crypto.falcon.FalconPrivateKeyParameters;
import org.bouncycastle.pqc.crypto.falcon.FalconSigner;
import org.bouncycastle.pqc.crypto.falcon.FalconKeyGenerationParameters;
import org.bouncycastle.pqc.crypto.falcon.FalconKeyPairGenerator;


public class FalconCreateSigned extends TestCase
{
    public void testCreateSigned() 
        throws Exception
    {
        String[] files;
        files = new String[]{
            "keypairs_ref_falcon512.rsp",
            "keypairs_ref_falcon1024.rsp",
        };

        String[] newFiles = new String[]{
            "signed_java_falcon512.rsp",
            "signed_java_falcon1024.rsp",
        };
        FalconParameters[] paramList = new FalconParameters[]{
            FalconParameters.falcon_512,
            FalconParameters.falcon_1024,
        };

        for (int fileIndex = 0; fileIndex < files.length; fileIndex++)
        {
            String newFileName = newFiles[fileIndex];
            try {
            File myObj = new File("src/test/java/org/bouncycastle/pqc/crypto/test/additionalTesting/resources/falcon/interoperability/"+newFileName);
            if (myObj.createNewFile()) {
                    System.out.println("File created: " + myObj.getName());
            } else {
                    System.out.println("File already exists.");
            }
            } catch (IOException e) {
                System.out.println("An error occurred.");
                e.printStackTrace();
            }
            
            FileWriter newFile = new FileWriter("src/test/java/org/bouncycastle/pqc/crypto/test/additionalTesting/resources/falcon/interoperability/"+newFileName);
            String name = files[fileIndex];
            System.out.println("testing: " + name);
            InputStream src = FalconCreateSigned.class.getResourceAsStream("/org/bouncycastle/pqc/crypto/test/additionalTesting/resources/falcon/interoperability/" + name);
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
                
                //Get Seed
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
                //Get Public Key
                int publicKeyIndex = line.indexOf("pk = ");
                String publicKeyString = line.substring(publicKeyIndex + "pk = ".length()).trim();
                line = br.readLine();
                //Get Secret Key
                int secretKeyIndex = line.indexOf("sk = ");
                String secretKeyString = line.substring(secretKeyIndex + "sk = ".length()).trim();
                line = br.readLine();

                //convert all into byte arrays
                byte[] seedOld = Hex.decode(seedString); 
                byte[] sk = Hex.decode(secretKeyString);
                byte[] msg = Hex.decode(messageString);

                byte[] shortSK = Arrays.copyOfRange(sk, 1, sk.length);

                System.out.println("Testing Case: "+count);

                byte[] seed = new byte[48];
                byte[] entropy_input = new byte[48];
                for (int i=0;i<48;i++){
                    entropy_input[i]=(byte)i;
                }

                //Get Parameters
                FalconParameters params = paramList[fileIndex];
                //Generate Random from seed (assume this works correctly)
                NISTSecureRandom random = new NISTSecureRandom(entropy_input, null);

                FalconPrivateKeyParameters privateKeyParams = new FalconPrivateKeyParameters(params, shortSK);
                
                FalconSigner signer = new FalconSigner();
                ParametersWithRandom skwrand = new ParametersWithRandom(privateKeyParams, random);
                signer.init(true, skwrand);
                byte[] sig = signer.generateSignature(msg);
                byte[] ressm = new byte[2 + msg.length + sig.length - 1];
                //huhhhh surely this should all be abstracted
                ressm[0] = (byte)((sig.length - 40 - 1) >>> 8);
                ressm[1] = (byte)(sig.length - 40 - 1);
                System.arraycopy(sig, 1, ressm, 2, 40);
                System.arraycopy(msg, 0, ressm, 2 + 40, msg.length);
                System.arraycopy(sig, 40 + 1, ressm, 2 + 40 + msg.length, sig.length - 40 - 1);

                newFile.write("count = "+count+"\n");
                newFile.write("pk = "+publicKeyString+"\n");
                newFile.write("mlen = "+mlenString+"\n");
                newFile.write("msg = "+messageString+"\n");
                newFile.write("smlen = "+Integer.toString(ressm.length)+"\n");
                newFile.write("sm = "+Hex.toHexString(ressm)+"\n");

                newFile.write("\n");
                System.out.println("All Passed");
            }
            newFile.close();
        }
    }
}