package org.bouncycastle.pqc.crypto.test.additionalTesting.tests.sike;

import junit.framework.TestCase;
import java.io.*;


import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.pqc.crypto.test.NISTSecureRandom;

import org.bouncycastle.crypto.SecretWithEncapsulation;
import org.bouncycastle.pqc.crypto.sike.SIKEKEMGenerator;
import org.bouncycastle.pqc.crypto.sike.SIKEParameters;
import org.bouncycastle.pqc.crypto.sike.SIKEPublicKeyParameters;

public class SikeCreateEncapsulations extends TestCase
{
    public void testCreateEncapsulationsSIKE() 
        throws Exception
    {
        String[] files;
        files = new String[]{
            "keypairs_ref_374.rsp",
            "keypairs_ref_434.rsp",
            "keypairs_ref_524.rsp",
            "keypairs_ref_644.rsp",
        };

        String[] newFiles = new String[]{
            "encapsulation_java_374.rsp",
            "encapsulation_java_434.rsp",
            "encapsulation_java_524.rsp",
            "encapsulation_java_644.rsp",
        };

        SIKEParameters[] paramList = {
            SIKEParameters.sikep434,
            SIKEParameters.sikep503,
            SIKEParameters.sikep610,
            SIKEParameters.sikep751,
        };

        for (int fileIndex = 0; fileIndex < files.length; fileIndex++)
        {
            String newFileName = newFiles[fileIndex];
            try {
            File myObj = new File("src/test/java/org/bouncycastle/pqc/crypto/test/additionalTesting/resources/sike/interoperability/"+newFileName);
            if (myObj.createNewFile()) {
                    System.out.println("File created: " + myObj.getName());
            } else {
                    System.out.println("File already exists.");
            }
            } catch (IOException e) {
                System.out.println("An error occurred.");
                e.printStackTrace();
            }
            
            FileWriter newFile = new FileWriter("src/test/java/org/bouncycastle/pqc/crypto/test/additionalTesting/resources/sike/interoperability/"+newFileName);
            String name = files[fileIndex];
            System.out.println("testing: " + name);
            InputStream src = SikeCreateEncapsulations.class.getResourceAsStream("/org/bouncycastle/pqc/crypto/test/additionalTesting/resources/sike/interoperability/" + name);
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
                SIKEParameters params = paramList[fileIndex];
                //Generate Random from seed (assume this works correctly)
                NISTSecureRandom random = new NISTSecureRandom(entropy_input, null);

                SIKEPublicKeyParameters publicKeyParams = new SIKEPublicKeyParameters(params, pk);

                SIKEKEMGenerator encapsulator = new SIKEKEMGenerator(random);
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