package org.bouncycastle.pqc.crypto.test.additionalTesting.tests.saber;

import junit.framework.TestCase;
import java.io.*;

//Dependencies Written by Bouncy Castle
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.pqc.crypto.test.NISTSecureRandom;

import org.bouncycastle.crypto.SecretWithEncapsulation;
//Asset Under Test
import org.bouncycastle.pqc.crypto.saber.SABERKEMGenerator;
import org.bouncycastle.pqc.crypto.saber.SABERParameters;
import org.bouncycastle.pqc.crypto.saber.SABERPublicKeyParameters;


public class SaberCreateEncapsulations extends TestCase
{
    public void testCreateEncapsulationsSABER() 
        throws Exception
    {
        String[] files;
        files = new String[]{
            "keypairs_ref_1568.rsp",
            "keypairs_ref_2304.rsp",
            "keypairs_ref_3040.rsp",
        };

        String[] newFiles = new String[]{
            "encapsulation_java_1568.rsp",
            "encapsulation_java_2304.rsp",
            "encapsulation_java_3040.rsp",
        };

        SABERParameters[] paramList = new SABERParameters[]{
            SABERParameters.lightsaberkem256r3,
            SABERParameters.saberkem256r3,
            SABERParameters.firesaberkem256r3,
        };

        for (int fileIndex = 0; fileIndex < files.length; fileIndex++)
        {
            String newFileName = newFiles[fileIndex];
            try {
            File myObj = new File("src/test/java/org/bouncycastle/pqc/crypto/test/additionalTesting/resources/saber/interoperability/"+newFileName);
            if (myObj.createNewFile()) {
                    System.out.println("File created: " + myObj.getName());
            } else {
                    System.out.println("File already exists.");
            }
            } catch (IOException e) {
                System.out.println("An error occurred.");
                e.printStackTrace();
            }
            
            FileWriter newFile = new FileWriter("src/test/java/org/bouncycastle/pqc/crypto/test/additionalTesting/resources/saber/interoperability/"+newFileName);
            String name = files[fileIndex];
            System.out.println("testing: " + name);
            InputStream src = SaberCreateEncapsulations.class.getResourceAsStream("/org/bouncycastle/pqc/crypto/test/additionalTesting/resources/saber/interoperability/" + name);
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
                byte[] pk = Hex.decode(publicKeyString);

                System.out.println("Testing Case: "+count);

                byte[] seed = new byte[48];
                byte[] entropy_input = new byte[48];
                for (int i=0;i<48;i++){
                    entropy_input[i]=(byte)i;
                }

                //Get Parameters
                SABERParameters params = paramList[fileIndex];
                //Generate Random from seed (assume this works correctly)
                NISTSecureRandom random = new NISTSecureRandom(entropy_input, null);

                SABERPublicKeyParameters publicKeyParams = new SABERPublicKeyParameters(params, pk);

                SABERKEMGenerator encapsulator = new SABERKEMGenerator(random);
                SecretWithEncapsulation encapsulatedSecret = encapsulator.generateEncapsulated(publicKeyParams);
                byte[] returnedCt = encapsulatedSecret.getEncapsulation();
                byte[] returnedSecret = encapsulatedSecret.getSecret();

                newFile.write("count = "+count+"\n");
                newFile.write("pk = "+publicKeyString+"\n");
                newFile.write("sk = "+secretKeyString+"\n");
                newFile.write("ct = "+Hex.toHexString(returnedCt)+"\n");
                newFile.write("ss = "+Hex.toHexString(returnedSecret)+"\n");
                newFile.write("\n");
                System.out.println("All Passed");
            }
            newFile.close();
        }
    }
}