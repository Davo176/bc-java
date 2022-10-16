package org.bouncycastle.pqc.crypto.test.additionalTesting.tests.dilithium;

import junit.framework.TestCase;
import java.io.*;

//Dependencies Written by Bouncy Castle
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.pqc.crypto.test.NISTSecureRandom;
import org.bouncycastle.util.Arrays;

import org.bouncycastle.crypto.SecretWithEncapsulation;
//Asset Under Test
import org.bouncycastle.pqc.crypto.crystals.dilithium.DilithiumParameters;
import org.bouncycastle.pqc.crypto.crystals.dilithium.DilithiumPublicKeyParameters;
import org.bouncycastle.pqc.crypto.crystals.dilithium.DilithiumPrivateKeyParameters;
import org.bouncycastle.pqc.crypto.crystals.dilithium.DilithiumSigner;
import org.bouncycastle.pqc.crypto.crystals.dilithium.DilithiumKeyGenerationParameters;
import org.bouncycastle.pqc.crypto.crystals.dilithium.DilithiumKeyPairGenerator;


public class DilithiumCreateSigned extends TestCase
{
    public void testCreateEncapsulationsBike() 
        throws Exception
    {
        String[] files;
        files = new String[]{
            "keypairs_ref_Dilithium2.rsp",
            "keypairs_ref_Dilithium3.rsp",
            "keypairs_ref_Dilithium5.rsp",
        };

        String[] newFiles = new String[]{
            "signed_java_Dilithium2.rsp",
            "signed_java_Dilithium3.rsp",
            "signed_java_Dilithium5.rsp"
        };
        DilithiumParameters[] paramList = new DilithiumParameters[]{
            DilithiumParameters.dilithium2,
            DilithiumParameters.dilithium3,
            DilithiumParameters.dilithium5
        };

        for (int fileIndex = 0; fileIndex < files.length; fileIndex++)
        {
            String newFileName = newFiles[fileIndex];
            try {
            File myObj = new File("src/test/java/org/bouncycastle/pqc/crypto/test/additionalTesting/resources/dilithium/interoperability/"+newFileName);
            if (myObj.createNewFile()) {
                    System.out.println("File created: " + myObj.getName());
            } else {
                    System.out.println("File already exists.");
            }
            } catch (IOException e) {
                System.out.println("An error occurred.");
                e.printStackTrace();
            }
            
            FileWriter newFile = new FileWriter("src/test/java/org/bouncycastle/pqc/crypto/test/additionalTesting/resources/dilithium/interoperability/"+newFileName);
            String name = files[fileIndex];
            System.out.println("testing: " + name);
            InputStream src = DilithiumCreateSigned.class.getResourceAsStream("/org/bouncycastle/pqc/crypto/test/additionalTesting/resources/dilithium/interoperability/" + name);
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

                System.out.println("Testing Case: "+count);

                byte[] seed = new byte[48];
                byte[] entropy_input = new byte[48];
                for (int i=0;i<48;i++){
                    entropy_input[i]=(byte)i;
                }

                //Get Parameters
                DilithiumParameters params = paramList[fileIndex];
                //Generate Random from seed (assume this works correctly)
                NISTSecureRandom random = new NISTSecureRandom(entropy_input, null);

                DilithiumPrivateKeyParameters privateKeyParams = new DilithiumPrivateKeyParameters(params, sk,random);
                
                DilithiumSigner signer = new DilithiumSigner();
                signer.init(true, privateKeyParams);

                byte[] sigGenerated = signer.generateSignature(msg);
                byte[] attachedSig = Arrays.concatenate(sigGenerated, msg);

                newFile.write("count = "+count+"\n");
                newFile.write("pk = "+publicKeyString+"\n");
                newFile.write("mlen = "+mlenString+"\n");
                newFile.write("msg = "+messageString+"\n");
                newFile.write("smlen = "+Integer.toString(attachedSig.length)+"\n");
                newFile.write("sm = "+Hex.toHexString(attachedSig)+"\n");

                newFile.write("\n");
                System.out.println("All Passed");
            }
            newFile.close();
        }
    }
}